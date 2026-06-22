"""Live flow assembly for the serving path.

Wraps a `FlowTracker` so the capture / replay loops can feed it raw packets and
get back **scored flow events** without each loop reimplementing flow assembly.

Two emission triggers:
1. A flow naturally completes/expires (TCP RST/FIN, idle/active timeout) - it is
   scored once, finalised.
2. A flow is still open but has grown enough to be worth an *interim* score, so
   the dashboard shows activity live instead of waiting for slow flows to close.
   Interim scores are recomputed as the flow grows (debounced by packet count).

Each emitted event is a dict: {features, metadata, final: bool}.
"""

from __future__ import annotations

from typing import Any, Callable

from src.core.flow_tracker import FlowTracker

# Score an open flow for the first time once it reaches this many packets, then
# re-score every INTERIM_STEP additional packets, so live flows surface quickly.
INTERIM_MIN_PACKETS = 2
INTERIM_STEP = 6


def _metadata(flow, protocol_name: Callable[[Any], str]) -> dict[str, Any]:
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "protocol": protocol_name(flow.protocol),
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
    }


class LiveFlowSource:
    def __init__(self, protocol_name: Callable[[Any], str]):
        self.tracker = FlowTracker()
        self.protocol_name = protocol_name
        # remember last interim packet-count scored per flow key (debounce)
        self._interim_at: dict[tuple, int] = {}

    def feed(self, pkt: dict[str, Any]) -> list[dict[str, Any]]:
        """Feed one packet; return zero or more scored flow events."""
        events: list[dict[str, Any]] = []

        completed = self.tracker.add_packet(pkt)
        for flow in completed:
            events.append(
                {
                    "features": flow.to_features(),
                    "metadata": _metadata(flow, self.protocol_name),
                    "final": True,
                }
            )
            self._interim_at.pop(flow.key(), None)

        # interim score for the still-open flow this packet belongs to
        key, _ = FlowTracker._canonical(pkt)
        live = self.tracker.flows.get(key)
        if live is not None:
            n = live.packet_count()
            last = self._interim_at.get(key, 0)
            if n >= INTERIM_MIN_PACKETS and (n - last) >= (
                INTERIM_STEP if last else 1
            ):
                self._interim_at[key] = n
                events.append(
                    {
                        "features": live.to_features(),
                        "metadata": _metadata(live, self.protocol_name),
                        "final": False,
                    }
                )
        return events

    def flush(self) -> list[dict[str, Any]]:
        events = []
        for flow in self.tracker.flush():
            events.append(
                {
                    "features": flow.to_features(),
                    "metadata": _metadata(flow, self.protocol_name),
                    "final": True,
                }
            )
        self._interim_at.clear()
        return events
