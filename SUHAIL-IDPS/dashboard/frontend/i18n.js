/* SUHAIL-IDPS dashboard localisation.
 *
 * Three locales: English (en), Afghan Dari (fa-AF) and Pashto (ps). Dari and
 * Pashto are right-to-left, so switching a locale also flips <html dir> and the
 * document font stack; app.css carries the matching [dir="rtl"] overrides.
 *
 * Coverage is total: every static label in index.html is tagged with a
 * data-i18n* attribute and resolved here, and every string app.js builds at
 * runtime goes through t(). Text that the Flask backend produces in English
 * (decision reasons, response messages, block reasons) is mapped back to keys by
 * serverText() / serverReason() so no English leaks through the live feed.
 *
 * Digits stay Latin in every locale — IPs, ports, scores and thresholds are
 * read against tooling that speaks Latin numerals.
 */
(() => {
  "use strict";

  // `preload` lists the faces a locale paints most of its text with, so they are
  // fetched in parallel with the stylesheet instead of after it. Latin runs
  // (XGB, IPs, iptables) use Inter in every locale — see the stacks in app.css.
  const LOCALES = {
    en: {
      name: "English", native: "English", dir: "ltr",
      preload: ["fonts/Inter-Regular.woff2", "fonts/Inter-Bold.woff2"],
    },
    "fa-AF": {
      name: "Dari", native: "دری", dir: "rtl",
      preload: ["fonts/BNazanin-Regular.woff2", "fonts/Inter-Regular.woff2"],
    },
    ps: {
      name: "Pashto", native: "پښتو", dir: "rtl",
      preload: ["fonts/NotoNaskhArabic-Regular.woff2", "fonts/NotoNaskhArabic-Bold.woff2",
                "fonts/Inter-Regular.woff2"],
    },
  };
  const DEFAULT_LOCALE = "en";
  const STORAGE_KEY = "suhail-idps.locale";

  // ------------------------------------------------------------------ strings
  const STRINGS = {
    en: {
      // ---- shell / brand
      "app.title": "SUHAIL IDPS · Live Console",
      "brand.name": "SUHAIL IDPS",
      "brand.tagline": "Flow-based three-barrier AI",
      "lang.label": "Language",

      // ---- nav
      "nav.overview": "Overview",
      "nav.live": "Live Traffic",
      "nav.alerts": "Alerts",
      "nav.sources": "Sources & Blocking",
      "nav.models": "Models",
      "nav.settings": "Settings",

      // ---- side card
      "side.barriers": "Barriers",
      "side.barrier1": "1 · Routine — XGBoost",
      "side.barrier2": "2 · Context — Transformer",
      "side.barrier3": "3 · Zero-day — Autoencoder",
      "side.captureIdle": "Capture idle",
      "side.capturingOn": "Capturing on {iface} [{filter}]",
      "engine.trainedModels": "trained models",
      "engine.surrogateMode": "surrogate mode",

      // ---- connection state
      "live.connecting": "Connecting",
      "live.live": "Live",
      "live.reconnecting": "Reconnecting",
      "live.polling": "Polling",
      "live.offline": "Backend offline",

      // ---- overview
      "ov.title": "Live Intrusion Detection & Prevention",
      "ov.subtitle":
        "Bidirectional flows scored by a routine classifier, a context transformer and a zero-day anomaly detector — one live decision stream.",
      "ov.totalFlows": "Total flows",
      "ov.flowsPerMin": "{n} flows/min",
      "ov.normal": "Normal",
      "ov.uptime": "{n}m uptime",
      "ov.suspicious": "Suspicious",
      "ov.underReview": "Under review",
      "ov.attacks": "Attacks",
      "ov.attackRate": "{p} attack rate",
      "ov.blocked": "Blocked",
      "ov.activeEntries": "Active entries",
      "ov.decision": "Three-Barrier AI Decision",
      "ov.noFlowsYet": "No flows yet",
      "ov.hostCtx": "Host ctx {n}/{m}",
      "ov.hostCtxEarly": " (early)",
      "ov.timeline": "Threat Timeline",
      "ov.protoMix": "Protocol Mix",
      "ov.modelHealth": "Model Health",
      "ov.engineStatusHint": "live engine status",

      // ---- barrier cards
      "barrier.routine": "Routine",
      "barrier.routineRole": "XGBoost · per-flow classifier",
      "barrier.context": "Context",
      "barrier.contextRole": "Transformer · flow sequence",
      "barrier.zero": "Zero-day",
      "barrier.zeroRole": "Autoencoder · anomaly",

      // ---- legend
      "legend.safe": "safe",
      "legend.elevated": "elevated",
      "legend.threat": "threat",

      // ---- live traffic
      "livep.title": "Live Traffic",
      "livep.subtitle":
        "Capture from any interface, replay synthetic flows, and inspect every scored flow.",
      "livep.captureTitle": "Live Capture · this machine",
      "livep.rootRequired": "root required",
      "livep.iface": "Interface (packet source)",
      "livep.allInterfaces": "All interfaces",
      "livep.ifaceHelp": "Where packets are captured and assembled into flows",
      "livep.protoFilter": "Protocol filter",
      "livep.any": "Any",
      "livep.srcFilter": "Source IP filter",
      "livep.srcFilterPlaceholder": "e.g. 10.0.0.5",
      "livep.srcFilterHelp": "Only capture packets from this source",
      "livep.startCapture": "▶ Start Capture",
      "livep.stop": "■ Stop",
      "livep.replayTitle": "Flow Replay",
      "livep.replayHint": "synthetic demo traffic",
      "livep.profile": "Profile",
      "livep.profileMixed": "Mixed",
      "livep.profileAttack": "Attack only",
      "livep.profileNormal": "Normal only",
      "livep.speed": "Speed (flows/s)",
      "livep.startReplay": "▶ Start Replay",
      "livep.replayHelp":
        'Replays real flows from <span class="mono">data/flows/all_flows.csv</span> if present, else generates normal + attack flows (port-scan, SYN/UDP flood, slow-DoS).',
      "livep.eventsTitle": "Live Flow Events",
      "livep.filterSrcPlaceholder": "Filter source IP",
      "livep.allStatuses": "All statuses",
      "livep.pause": "Pause",
      "livep.resume": "Resume",
      "livep.export": "⭳ Export",
      "livep.tableHelp":
        "Click a flow to drill into its barrier-by-barrier history and feature breakdown. Italic rows are interim (open) flows.",

      // ---- table headers
      "th.time": "Time",
      "th.status": "Status",
      "th.source": "Source",
      "th.destination": "Destination",
      "th.proto": "Proto",
      "th.pkts": "Pkts",
      "th.threat": "Threat",
      "th.reason": "Reason",
      "th.action": "Action",
      "th.severity": "Severity",
      "th.type": "Type",
      "th.xgb": "XGB",
      "th.transformer": "Transformer",
      "th.ae": "AE",

      // ---- alerts
      "alerts.title": "Alerts",
      "alerts.subtitle": "Every suspicious and hostile decision the barriers raised.",
      "alerts.total": "Total alerts:",
      "alerts.feed": "Alert Feed",
      "alerts.feedHint": "click a row for flow detail",

      // ---- sources
      "src.title": "Sources & Blocking",
      "src.subtitle": "Per-source intelligence and the active prevention list.",
      "src.hotSources": "Hot Sources",
      "src.rankedByAttacks": "ranked by attacks",
      "src.blockedIps": "Blocked IPs",
      "src.autoManual": "auto + manual",
      "src.stats": "{total} pkts · {attacks} attacks · {suspicious} suspicious",
      "src.blockMeta": "{mode} · {reason} · until {time}",
      "src.dryRun": "Dry-run",
      "src.enforced": "Enforced",
      "btn.block": "Block",
      "btn.unblock": "Unblock",

      // ---- models
      "models.title": "Models",
      "models.subtitle": "The three barriers, how they're running, and the active thresholds.",
      "models.reload": "↻ Reload Models",
      "models.banner":
        'One or more barriers run in <b>surrogate</b> mode (dependency-free approximation on flow features). Collect data &amp; train (see <span class="mono">DATA_COLLECTION.md</span>), install XGBoost + TensorFlow, then <b>Reload Models</b> to serve the trained models.',
      "models.engineConfig": "Engine Configuration",
      "models.featureSpace": "Feature space:",
      "models.flowFeatures": "flow features",
      "models.contextWindow": "Context window:",
      "models.flowsPerHost": "flows/host",
      "models.earlyContext": "Early context:",
      "models.padEnabled": "Enabled (early reads)",
      "models.padStrict": "Strict (full window)",
      "models.attackTyping": "Attack typing:",
      "models.route": "Route",
      "models.features": "Features:",
      "models.activeThresholds": "Active Thresholds",
      "role.xgboost": "Barrier 1 - routine per-packet classifier",
      "role.transformer": "Barrier 2 - session context (broader view)",
      "role.autoencoder": "Barrier 3 - zero-day anomaly detector",
      "thr.xgb_suspicious": "xgb_suspicious",
      "thr.xgb_attack": "xgb_attack",
      "thr.transformer": "transformer",
      "thr.autoencoder": "autoencoder",

      // ---- settings
      "set.title": "Settings",
      "set.subtitle":
        "Tune the decision thresholds and the prevention policy. Changes persist across restarts.",
      "set.save": "Save & Persist",
      "set.thresholds": "Decision Thresholds",
      "set.perBarrier": "per barrier",
      "set.xgbSuspicious": "XGB suspicious",
      "set.xgbSuspiciousHelp": "Routine warn level",
      "set.xgbAttack": "XGB attack",
      "set.xgbAttackHelp": "Routine hard-block level",
      "set.transformer": "Transformer",
      "set.transformerHelp": "Sequence attack level",
      "set.autoencoder": "Autoencoder",
      "set.autoencoderHelp": "Reconstruction-error cutoff",
      "set.policy": "Prevention Policy",
      "set.policyHint": "response & blocking",
      "set.autoBlock": "Auto-block offenders",
      "set.dryRun": "Dry-run (simulate)",
      "set.blockThreshold": "Block after N alerts",
      "set.blockDuration": "Block duration (sec)",
      "set.policyHelp":
        'When dry-run is off, blocks run real <span class="mono">iptables -A INPUT -s &lt;ip&gt; -j DROP</span> rules and the backend must run as root.',

      // ---- modal
      "btn.close": "Close",
      "modal.loading": "Loading...",
      "modal.noRecentFlows": "No recent flows for this host.",
      "modal.loadFailed": "Could not load flow.",
      "modal.latestFeatures": "Latest flow features",
      "feat.total_packets": "Packets",
      "feat.total_bytes": "Bytes",
      "feat.flow_duration": "Duration s",
      "feat.flow_pkts_per_s": "Pkts/s",
      "feat.down_up_ratio": "Down/Up",
      "feat.syn_flag_count": "SYN",
      "feat.rst_flag_count": "RST",
      "feat.pkt_len_mean": "Avg len",

      // ---- empty states
      "empty.noEvents": "No matching events yet.",
      "empty.noAlerts": "No alerts yet.",
      "empty.noSources": "No sources observed.",
      "empty.noBlocks": "No active blocks.",

      // ---- statuses (badge) + plural filter labels
      "status.NORMAL": "NORMAL",
      "status.SUSPICIOUS": "SUSPICIOUS",
      "status.ATTACK": "ATTACK",
      "status.UNKNOWN": "UNKNOWN",
      "statusPlural.NORMAL": "Normal",
      "statusPlural.SUSPICIOUS": "Suspicious",
      "statusPlural.ATTACK": "Attacks",
      "statusPlural.UNKNOWN": "Unknown",

      // ---- barrier states
      "state.WAITING": "Waiting",
      "state.PASS": "Pass",
      "state.ALERT": "Alert",
      "state.UNAVAILABLE": "Unavailable",

      // ---- severities
      "sev.critical": "critical",
      "sev.high": "high",
      "sev.medium": "medium",
      "sev.low": "low",

      // ---- engine modes
      "mode.model": "model",
      "mode.surrogate": "surrogate",
      "mode.unavailable": "unavailable",
      "mode.heuristic": "heuristic",
      "route.A": "A (heuristic)",
      "route.B": "B (multi-class model)",

      // ---- response actions
      "action.observe": "observe",
      "action.watch": "watch",
      "action.block": "block",
      "action.blocked": "blocked",
      "action.unblock": "unblock",

      // ---- attack archetypes
      "atype.portscan": "PORT SCAN",
      "atype.synflood": "SYN FLOOD",
      "atype.udpflood": "UDP FLOOD",
      "atype.icmpflood": "ICMP FLOOD",
      "atype.httpflood": "HTTP FLOOD",
      "atype.slowloris": "SLOWLORIS",
      "atype.dos": "DOS",
      "atype.anomaly": "ANOMALY",

      // ---- backend decision reasons
      "reason.transformerConfirmed": "Transformer confirmed hostile flow-sequence context.",
      "reason.transformerPartial": "Transformer flagged the host on partial (early) context.",
      "reason.bothCrossed": "Routine classifier and anomaly detector both crossed attack policy.",
      "reason.xgbAttack": "Routine XGBoost barrier crossed attack threshold.",
      "reason.suspOutsideRecon": "Flow is suspicious and outside normal reconstruction range.",
      "reason.aeOutOfOrdinary": "Autoencoder found an out-of-ordinary flow.",
      "reason.xgbSuspicious": "Routine XGBoost barrier marked the flow suspicious.",
      "reason.noModel": "No model was available to score this flow.",
      "reason.allBelow": "All available barriers are below policy thresholds.",
      "reason.captureFailed": "Live capture could not start (need root / valid interface).",
      "reason.manual": "manual",
      "reason.autoBlock": "auto-block: {count} alerts ≥ {threshold}",

      // ---- backend response messages
      "msg.noSourceIp": "No source IP available.",
      "msg.belowThreshold": "Below response threshold.",
      "msg.alreadyBlocked": "{ip} already blocked ({count} alerts).",
      "msg.blockRegistered": "Block registered for {ip}.",
      "msg.watch": "{count}/{threshold} alert(s) from source{tail}",
      "msg.autoBlockIn": " · auto-block in {n} more alert(s).",
      "msg.autoBlockOff": " · auto-block off.",

      // ---- toasts
      "toast.autoBlocked": "AUTO-BLOCKED",
      "toast.settingsSaved": "Settings saved &amp; persisted.",
      "toast.modelsReloaded": "Models reloaded.",
      "toast.blockRegistered": "Block registered for {ip}.",
      "toast.captureFailed": "Capture failed: {error}",
      "toast.backendOffline": "Backend offline - start the Flask server.",

      // ---- units
      "unit.ms": "{n} ms",
      "unit.rawMse": "raw {n} MSE",
      "unit.rawProb": "raw {n} prob",
      "unit.mse": "{n} MSE",
      "unit.source": "source",
    },

    // ===================================================================== DARI
    "fa-AF": {
      "app.title": "سهیل IDPS · کنسول زنده",
      "brand.name": "سهیل IDPS",
      "brand.tagline": "هوش مصنوعی سه‌مانعی مبتنی بر جریان",
      "lang.label": "زبان",

      "nav.overview": "نمای کلی",
      "nav.live": "ترافیک زنده",
      "nav.alerts": "هشدارها",
      "nav.sources": "منابع و مسدودسازی",
      "nav.models": "مدل‌ها",
      "nav.settings": "تنظیمات",

      "side.barriers": "موانع",
      "side.barrier1": "۱ · معمولی — XGBoost",
      "side.barrier2": "۲ · زمینه — ترانسفورمر",
      "side.barrier3": "۳ · روز صفر — خودرمزگذار",
      "side.captureIdle": "ضبط غیرفعال",
      "side.capturingOn": "در حال ضبط روی {iface} [{filter}]",
      "engine.trainedModels": "مدل‌های آموزش‌دیده",
      "engine.surrogateMode": "حالت جایگزین",

      "live.connecting": "در حال اتصال",
      "live.live": "زنده",
      "live.reconnecting": "اتصال مجدد",
      "live.polling": "دریافت دوره‌ای",
      "live.offline": "بک‌اند آفلاین",

      "ov.title": "کشف و جلوگیری زندۀ نفوذ",
      "ov.subtitle":
        "جریان‌های دوطرفه توسط یک طبقه‌بند معمولی، یک ترانسفورمر زمینه و یک آشکارساز ناهنجاری روز صفر امتیازدهی می‌شوند — یک جریان تصمیم‌گیری زنده.",
      "ov.totalFlows": "مجموع جریان‌ها",
      "ov.flowsPerMin": "{n} جریان در دقیقه",
      "ov.normal": "عادی",
      "ov.uptime": "{n} دقیقه فعالیت",
      "ov.suspicious": "مشکوک",
      "ov.underReview": "در حال بررسی",
      "ov.attacks": "حملات",
      "ov.attackRate": "نرخ حمله {p}",
      "ov.blocked": "مسدود شده",
      "ov.activeEntries": "موارد فعال",
      "ov.decision": "تصمیم هوش مصنوعی سه‌مانعی",
      "ov.noFlowsYet": "هنوز جریانی نیست",
      "ov.hostCtx": "زمینۀ میزبان {n}/{m}",
      "ov.hostCtxEarly": " (زودهنگام)",
      "ov.timeline": "خط زمانی تهدید",
      "ov.protoMix": "ترکیب پروتوکول‌ها",
      "ov.modelHealth": "سلامت مدل‌ها",
      "ov.engineStatusHint": "وضعیت زندۀ موتور",

      "barrier.routine": "معمولی",
      "barrier.routineRole": "XGBoost · طبقه‌بند هر جریان",
      "barrier.context": "زمینه",
      "barrier.contextRole": "ترانسفورمر · توالی جریان",
      "barrier.zero": "روز صفر",
      "barrier.zeroRole": "خودرمزگذار · ناهنجاری",

      "legend.safe": "امن",
      "legend.elevated": "بالا رفته",
      "legend.threat": "تهدید",

      "livep.title": "ترافیک زنده",
      "livep.subtitle":
        "از هر رابط شبکه ضبط کنید، جریان‌های مصنوعی را بازپخش کنید و هر جریان امتیازدهی‌شده را بررسی کنید.",
      "livep.captureTitle": "ضبط زنده · این ماشین",
      "livep.rootRequired": "نیاز به دسترسی root",
      "livep.iface": "رابط شبکه (منبع بسته‌ها)",
      "livep.allInterfaces": "همۀ رابط‌ها",
      "livep.ifaceHelp": "جایی که بسته‌ها ضبط و به جریان تبدیل می‌شوند",
      "livep.protoFilter": "فیلتر پروتوکول",
      "livep.any": "هر کدام",
      "livep.srcFilter": "فیلتر آدرس مبدأ",
      "livep.srcFilterPlaceholder": "مثلاً 10.0.0.5",
      "livep.srcFilterHelp": "فقط بسته‌های این مبدأ ضبط شوند",
      "livep.startCapture": "▶ شروع ضبط",
      "livep.stop": "■ توقف",
      "livep.replayTitle": "بازپخش جریان",
      "livep.replayHint": "ترافیک نمایشی مصنوعی",
      "livep.profile": "پروفایل",
      "livep.profileMixed": "ترکیبی",
      "livep.profileAttack": "فقط حمله",
      "livep.profileNormal": "فقط عادی",
      "livep.speed": "سرعت (جریان در ثانیه)",
      "livep.startReplay": "▶ شروع بازپخش",
      "livep.replayHelp":
        'در صورت وجود، جریان‌های واقعی را از <span class="mono">data/flows/all_flows.csv</span> بازپخش می‌کند؛ در غیر این صورت جریان‌های عادی و حمله (پویش پورت، سیل SYN/UDP، DoS کند) تولید می‌کند.',
      "livep.eventsTitle": "رویدادهای زندۀ جریان",
      "livep.filterSrcPlaceholder": "فیلتر آدرس مبدأ",
      "livep.allStatuses": "همۀ وضعیت‌ها",
      "livep.pause": "توقف",
      "livep.resume": "ادامه",
      "livep.export": "⭳ خروجی",
      "livep.tableHelp":
        "برای دیدن تاریخچۀ مانع‌به‌مانع و تفکیک ویژگی‌ها روی یک جریان کلیک کنید. سطرهای ایتالیک جریان‌های موقتی (باز) هستند.",

      "th.time": "زمان",
      "th.status": "وضعیت",
      "th.source": "مبدأ",
      "th.destination": "مقصد",
      "th.proto": "پروتوکول",
      "th.pkts": "بسته‌ها",
      "th.threat": "تهدید",
      "th.reason": "دلیل",
      "th.action": "اقدام",
      "th.severity": "شدت",
      "th.type": "نوع",
      "th.xgb": "XGB",
      "th.transformer": "ترانسفورمر",
      "th.ae": "خودرمزگذار",

      "alerts.title": "هشدارها",
      "alerts.subtitle": "هر تصمیم مشکوک و خصمانه‌ای که موانع صادر کرده‌اند.",
      "alerts.total": "مجموع هشدارها:",
      "alerts.feed": "فهرست هشدارها",
      "alerts.feedHint": "برای جزئیات جریان روی سطر کلیک کنید",

      "src.title": "منابع و مسدودسازی",
      "src.subtitle": "اطلاعات هر مبدأ و فهرست فعال پیشگیری.",
      "src.hotSources": "منابع پرخطر",
      "src.rankedByAttacks": "مرتب‌شده بر اساس حملات",
      "src.blockedIps": "آدرس‌های مسدود شده",
      "src.autoManual": "خودکار + دستی",
      "src.stats": "{total} بسته · {attacks} حمله · {suspicious} مشکوک",
      "src.blockMeta": "{mode} · {reason} · تا {time}",
      "src.dryRun": "اجرای آزمایشی",
      "src.enforced": "اعمال شده",
      "btn.block": "مسدود کردن",
      "btn.unblock": "رفع مسدودیت",

      "models.title": "مدل‌ها",
      "models.subtitle": "سه مانع، نحوۀ اجرای آن‌ها و آستانه‌های فعال.",
      "models.reload": "↻ بارگذاری مجدد مدل‌ها",
      "models.banner":
        'یک یا چند مانع در حالت <b>جایگزین</b> اجرا می‌شوند (تقریب بدون وابستگی بر پایۀ ویژگی‌های جریان). داده جمع‌آوری و آموزش دهید (به <span class="mono">DATA_COLLECTION.md</span> مراجعه کنید)، XGBoost و TensorFlow را نصب کنید، سپس <b>بارگذاری مجدد مدل‌ها</b> را بزنید تا مدل‌های آموزش‌دیده ارائه شوند.',
      "models.engineConfig": "پیکربندی موتور",
      "models.featureSpace": "فضای ویژگی:",
      "models.flowFeatures": "ویژگی جریان",
      "models.contextWindow": "پنجرۀ زمینه:",
      "models.flowsPerHost": "جریان به ازای هر میزبان",
      "models.earlyContext": "زمینۀ زودهنگام:",
      "models.padEnabled": "فعال (خوانش زودهنگام)",
      "models.padStrict": "سخت‌گیرانه (پنجرۀ کامل)",
      "models.attackTyping": "نوع‌شناسی حمله:",
      "models.route": "مسیر",
      "models.features": "ویژگی‌ها:",
      "models.activeThresholds": "آستانه‌های فعال",
      "role.xgboost": "مانع ۱ — طبقه‌بند معمولی هر بسته",
      "role.transformer": "مانع ۲ — زمینۀ نشست (نمای گسترده‌تر)",
      "role.autoencoder": "مانع ۳ — آشکارساز ناهنجاری روز صفر",
      "thr.xgb_suspicious": "XGB مشکوک",
      "thr.xgb_attack": "XGB حمله",
      "thr.transformer": "ترانسفورمر",
      "thr.autoencoder": "خودرمزگذار",

      "set.title": "تنظیمات",
      "set.subtitle":
        "آستانه‌های تصمیم و سیاست پیشگیری را تنظیم کنید. تغییرات پس از راه‌اندازی مجدد باقی می‌مانند.",
      "set.save": "ذخیره و ماندگارسازی",
      "set.thresholds": "آستانه‌های تصمیم",
      "set.perBarrier": "برای هر مانع",
      "set.xgbSuspicious": "XGB مشکوک",
      "set.xgbSuspiciousHelp": "سطح هشدار معمولی",
      "set.xgbAttack": "XGB حمله",
      "set.xgbAttackHelp": "سطح مسدودسازی قطعی معمولی",
      "set.transformer": "ترانسفورمر",
      "set.transformerHelp": "سطح حملۀ توالی",
      "set.autoencoder": "خودرمزگذار",
      "set.autoencoderHelp": "حد خطای بازسازی",
      "set.policy": "سیاست پیشگیری",
      "set.policyHint": "واکنش و مسدودسازی",
      "set.autoBlock": "مسدودسازی خودکار متخلفان",
      "set.dryRun": "اجرای آزمایشی (شبیه‌سازی)",
      "set.blockThreshold": "مسدود کردن پس از N هشدار",
      "set.blockDuration": "مدت مسدودسازی (ثانیه)",
      "set.policyHelp":
        'وقتی اجرای آزمایشی خاموش باشد، مسدودسازی‌ها قواعد واقعی <span class="mono">iptables -A INPUT -s &lt;ip&gt; -j DROP</span> را اجرا می‌کنند و بک‌اند باید با دسترسی root اجرا شود.',

      "btn.close": "بستن",
      "modal.loading": "در حال بارگذاری...",
      "modal.noRecentFlows": "جریان اخیری برای این میزبان وجود ندارد.",
      "modal.loadFailed": "جریان بارگذاری نشد.",
      "modal.latestFeatures": "ویژگی‌های آخرین جریان",
      "feat.total_packets": "بسته‌ها",
      "feat.total_bytes": "بایت",
      "feat.flow_duration": "مدت (ثانیه)",
      "feat.flow_pkts_per_s": "بسته در ثانیه",
      "feat.down_up_ratio": "پایین/بالا",
      "feat.syn_flag_count": "SYN",
      "feat.rst_flag_count": "RST",
      "feat.pkt_len_mean": "طول میانگین",

      "empty.noEvents": "هنوز رویداد منطبقی وجود ندارد.",
      "empty.noAlerts": "هنوز هشداری وجود ندارد.",
      "empty.noSources": "هیچ مبدائی مشاهده نشد.",
      "empty.noBlocks": "هیچ مسدودسازی فعالی وجود ندارد.",

      "status.NORMAL": "عادی",
      "status.SUSPICIOUS": "مشکوک",
      "status.ATTACK": "حمله",
      "status.UNKNOWN": "ناشناخته",
      "statusPlural.NORMAL": "عادی",
      "statusPlural.SUSPICIOUS": "مشکوک",
      "statusPlural.ATTACK": "حملات",
      "statusPlural.UNKNOWN": "ناشناخته",

      "state.WAITING": "در انتظار",
      "state.PASS": "عبور",
      "state.ALERT": "هشدار",
      "state.UNAVAILABLE": "در دسترس نیست",

      "sev.critical": "بحرانی",
      "sev.high": "بالا",
      "sev.medium": "متوسط",
      "sev.low": "پایین",

      "mode.model": "مدل",
      "mode.surrogate": "جایگزین",
      "mode.unavailable": "ناموجود",
      "mode.heuristic": "اکتشافی",
      "route.A": "A (اکتشافی)",
      "route.B": "B (مدل چندکلاسه)",

      "action.observe": "مشاهده",
      "action.watch": "زیر نظر",
      "action.block": "مسدودسازی",
      "action.blocked": "مسدود شده",
      "action.unblock": "رفع مسدودیت",

      "atype.portscan": "پویش پورت",
      "atype.synflood": "سیل SYN",
      "atype.udpflood": "سیل UDP",
      "atype.icmpflood": "سیل ICMP",
      "atype.httpflood": "سیل HTTP",
      "atype.slowloris": "اسلولوریس",
      "atype.dos": "منع سرویس",
      "atype.anomaly": "ناهنجاری",

      "reason.transformerConfirmed": "ترانسفورمر زمینۀ خصمانۀ توالی جریان را تأیید کرد.",
      "reason.transformerPartial": "ترانسفورمر میزبان را بر پایۀ زمینۀ ناقص (زودهنگام) نشانه‌گذاری کرد.",
      "reason.bothCrossed": "طبقه‌بند معمولی و آشکارساز ناهنجاری هر دو از سیاست حمله عبور کردند.",
      "reason.xgbAttack": "مانع معمولی XGBoost از آستانۀ حمله عبور کرد.",
      "reason.suspOutsideRecon": "جریان مشکوک است و خارج از محدودۀ عادی بازسازی قرار دارد.",
      "reason.aeOutOfOrdinary": "خودرمزگذار یک جریان غیرعادی یافت.",
      "reason.xgbSuspicious": "مانع معمولی XGBoost جریان را مشکوک علامت زد.",
      "reason.noModel": "هیچ مدلی برای امتیازدهی این جریان در دسترس نبود.",
      "reason.allBelow": "همۀ موانع در دسترس زیر آستانه‌های سیاست هستند.",
      "reason.captureFailed": "ضبط زنده آغاز نشد (نیاز به دسترسی root / رابط معتبر).",
      "reason.manual": "دستی",
      "reason.autoBlock": "مسدودسازی خودکار: {count} هشدار ≥ {threshold}",

      "msg.noSourceIp": "آدرس مبدأ در دسترس نیست.",
      "msg.belowThreshold": "زیر آستانۀ واکنش.",
      "msg.alreadyBlocked": "{ip} از قبل مسدود است ({count} هشدار).",
      "msg.blockRegistered": "مسدودسازی برای {ip} ثبت شد.",
      "msg.watch": "{count}/{threshold} هشدار از این مبدأ{tail}",
      "msg.autoBlockIn": " · مسدودسازی خودکار پس از {n} هشدار دیگر.",
      "msg.autoBlockOff": " · مسدودسازی خودکار خاموش است.",

      "toast.autoBlocked": "مسدودسازی خودکار",
      "toast.settingsSaved": "تنظیمات ذخیره و ماندگار شد.",
      "toast.modelsReloaded": "مدل‌ها دوباره بارگذاری شدند.",
      "toast.blockRegistered": "مسدودسازی برای {ip} ثبت شد.",
      "toast.captureFailed": "ضبط ناموفق بود: {error}",
      "toast.backendOffline": "بک‌اند آفلاین است — سرور Flask را اجرا کنید.",

      "unit.ms": "{n} میلی‌ثانیه",
      "unit.rawMse": "خام {n} MSE",
      "unit.rawProb": "خام {n} احتمال",
      "unit.mse": "{n} MSE",
      "unit.source": "مبدأ",
    },

    // =================================================================== PASHTO
    ps: {
      "app.title": "سهیل IDPS · ژوندۍ کنسول",
      "brand.name": "سهیل IDPS",
      "brand.tagline": "په جریان ولاړ درې‌خنډیز مصنوعي ذهانت",
      "lang.label": "ژبه",

      "nav.overview": "عمومي کتنه",
      "nav.live": "ژوندی ترافیک",
      "nav.alerts": "خبرتیاوې",
      "nav.sources": "سرچینې او بندول",
      "nav.models": "موډلونه",
      "nav.settings": "تنظیمات",

      "side.barriers": "خنډونه",
      "side.barrier1": "۱ · معمولي — XGBoost",
      "side.barrier2": "۲ · شالید — ټرانسفارمر",
      "side.barrier3": "۳ · صفر ورځ — آټو‌انکوډر",
      "side.captureIdle": "نیول ولاړ دي",
      "side.capturingOn": "په {iface} کې نیول روان دي [{filter}]",
      "engine.trainedModels": "روزل‌شوي موډلونه",
      "engine.surrogateMode": "بدیل حالت",

      "live.connecting": "په نښلولو کې",
      "live.live": "ژوندی",
      "live.reconnecting": "بیا نښلول",
      "live.polling": "دوره‌یي راټولول",
      "live.offline": "بیک‌اِنډ آفلاین",

      "ov.title": "د ننوتنې ژوندی کشف او مخنیوی",
      "ov.subtitle":
        "دوه‌اړخیز جریانونه د یوه معمولي کټګوري‌کوونکي، د شالید ټرانسفارمر او د صفر ورځې د بې‌قاعدګۍ کشفوونکي له خوا ارزول کیږي — یو ژوندی د پریکړې بهیر.",
      "ov.totalFlows": "ټول جریانونه",
      "ov.flowsPerMin": "{n} جریانه په دقیقه کې",
      "ov.normal": "عادي",
      "ov.uptime": "{n} دقیقې کار",
      "ov.suspicious": "شکمن",
      "ov.underReview": "تر څېړنې لاندې",
      "ov.attacks": "بریدونه",
      "ov.attackRate": "د برید کچه {p}",
      "ov.blocked": "بند شوي",
      "ov.activeEntries": "فعال ثبتونه",
      "ov.decision": "د درې‌خنډیز مصنوعي ذهانت پریکړه",
      "ov.noFlowsYet": "تر اوسه جریان نشته",
      "ov.hostCtx": "د کوربه شالید {n}/{m}",
      "ov.hostCtxEarly": " (وختي)",
      "ov.timeline": "د ګواښ مهال‌ویش",
      "ov.protoMix": "د پروتوکولونو ترکیب",
      "ov.modelHealth": "د موډلونو روغتیا",
      "ov.engineStatusHint": "د انجن ژوندی حالت",

      "barrier.routine": "معمولي",
      "barrier.routineRole": "XGBoost · د هر جریان کټګوري‌کوونکی",
      "barrier.context": "شالید",
      "barrier.contextRole": "ټرانسفارمر · د جریان لړۍ",
      "barrier.zero": "صفر ورځ",
      "barrier.zeroRole": "آټو‌انکوډر · بې‌قاعدګي",

      "legend.safe": "خوندي",
      "legend.elevated": "لوړ شوی",
      "legend.threat": "ګواښ",

      "livep.title": "ژوندی ترافیک",
      "livep.subtitle":
        "له هر انټرفیس څخه نیول وکړئ، مصنوعي جریانونه بیا وچلوئ او هر ارزول‌شوی جریان وڅېړئ.",
      "livep.captureTitle": "ژوندی نیول · دا ماشین",
      "livep.rootRequired": "د root واک ته اړتیا",
      "livep.iface": "انټرفیس (د پاکټونو سرچینه)",
      "livep.allInterfaces": "ټول انټرفیسونه",
      "livep.ifaceHelp": "هغه ځای چې پاکټونه نیول کیږي او په جریانونو بدلیږي",
      "livep.protoFilter": "د پروتوکول فلټر",
      "livep.any": "هر یو",
      "livep.srcFilter": "د سرچینې د IP فلټر",
      "livep.srcFilterPlaceholder": "لکه 10.0.0.5",
      "livep.srcFilterHelp": "یوازې د دې سرچینې پاکټونه ونیسئ",
      "livep.startCapture": "▶ نیول پیل کړئ",
      "livep.stop": "■ ودروئ",
      "livep.replayTitle": "د جریان بیا‌چلونه",
      "livep.replayHint": "مصنوعي ډیمو ترافیک",
      "livep.profile": "پروفایل",
      "livep.profileMixed": "ګډ",
      "livep.profileAttack": "یوازې برید",
      "livep.profileNormal": "یوازې عادي",
      "livep.speed": "سرعت (جریان په ثانیه کې)",
      "livep.startReplay": "▶ بیا‌چلونه پیل کړئ",
      "livep.replayHelp":
        'که شتون ولري، ریښتیني جریانونه له <span class="mono">data/flows/all_flows.csv</span> څخه بیا چلوي؛ که نه، عادي او بریدیز جریانونه (د پورټ سکن، د SYN/UDP سیلاب، ورو DoS) جوړوي.',
      "livep.eventsTitle": "د جریان ژوندۍ پېښې",
      "livep.filterSrcPlaceholder": "د سرچینې د IP فلټر",
      "livep.allStatuses": "ټول حالتونه",
      "livep.pause": "ودرول",
      "livep.resume": "دوام",
      "livep.export": "⭳ صادرول",
      "livep.tableHelp":
        "د خنډ‌په‌خنډ تاریخچې او د ځانګړتیاوو د ویش لیدو لپاره پر یوه جریان کلیک وکړئ. کږې کرښې لنډمهاله (خلاص) جریانونه دي.",

      "th.time": "وخت",
      "th.status": "حالت",
      "th.source": "سرچینه",
      "th.destination": "منزل",
      "th.proto": "پروتوکول",
      "th.pkts": "پاکټونه",
      "th.threat": "ګواښ",
      "th.reason": "دلیل",
      "th.action": "کړنه",
      "th.severity": "سختوالی",
      "th.type": "ډول",
      "th.xgb": "XGB",
      "th.transformer": "ټرانسفارمر",
      "th.ae": "آټو‌انکوډر",

      "alerts.title": "خبرتیاوې",
      "alerts.subtitle": "هره شکمنه او دښمنانه پریکړه چې خنډونو راپورته کړې.",
      "alerts.total": "ټولې خبرتیاوې:",
      "alerts.feed": "د خبرتیاوو لړ",
      "alerts.feedHint": "د جریان د جزیاتو لپاره پر کرښه کلیک وکړئ",

      "src.title": "سرچینې او بندول",
      "src.subtitle": "د هرې سرچینې معلومات او د مخنیوي فعاله لړ.",
      "src.hotSources": "ګواښونکې سرچینې",
      "src.rankedByAttacks": "د بریدونو له مخې ترتیب",
      "src.blockedIps": "بند شوي IP پتې",
      "src.autoManual": "اتوماتیک + لاسي",
      "src.stats": "{total} پاکټه · {attacks} بریده · {suspicious} شکمن",
      "src.blockMeta": "{mode} · {reason} · تر {time} پورې",
      "src.dryRun": "آزمایښتي چلول",
      "src.enforced": "پلی شوی",
      "btn.block": "بندول",
      "btn.unblock": "خلاصول",

      "models.title": "موډلونه",
      "models.subtitle": "درې خنډونه، د دوی د چلولو څرنګوالی، او فعالې کچې.",
      "models.reload": "↻ موډلونه بیا پورته کړئ",
      "models.banner":
        'یو یا څو خنډونه په <b>بدیل</b> حالت کې چلیږي (د جریان پر ځانګړتیاوو باندې بې‌اتکا اټکل). ډاټا راټوله او روزنه وکړئ (<span class="mono">DATA_COLLECTION.md</span> وګورئ)، XGBoost او TensorFlow نصب کړئ، بیا <b>موډلونه بیا پورته کړئ</b> ووهئ ترڅو روزل‌شوي موډلونه وړاندې شي.',
      "models.engineConfig": "د انجن تنظیمات",
      "models.featureSpace": "د ځانګړتیاوو ساحه:",
      "models.flowFeatures": "د جریان ځانګړتیاوې",
      "models.contextWindow": "د شالید کړکۍ:",
      "models.flowsPerHost": "جریانه په هر کوربه کې",
      "models.earlyContext": "وختی شالید:",
      "models.padEnabled": "فعال (وختي لوستل)",
      "models.padStrict": "سخت (بشپړه کړکۍ)",
      "models.attackTyping": "د برید ډول‌پېژندنه:",
      "models.route": "لار",
      "models.features": "ځانګړتیاوې:",
      "models.activeThresholds": "فعالې کچې",
      "role.xgboost": "خنډ ۱ — د هر پاکټ معمولي کټګوري‌کوونکی",
      "role.transformer": "خنډ ۲ — د ناستې شالید (پراخه کتنه)",
      "role.autoencoder": "خنډ ۳ — د صفر ورځې د بې‌قاعدګۍ کشفوونکی",
      "thr.xgb_suspicious": "XGB شکمن",
      "thr.xgb_attack": "XGB برید",
      "thr.transformer": "ټرانسفارمر",
      "thr.autoencoder": "آټو‌انکوډر",

      "set.title": "تنظیمات",
      "set.subtitle":
        "د پریکړې کچې او د مخنیوي پالیسي تنظیم کړئ. بدلونونه د بیا‌پیلولو وروسته هم پاتې کیږي.",
      "set.save": "خوندي او دایمي کول",
      "set.thresholds": "د پریکړې کچې",
      "set.perBarrier": "د هر خنډ لپاره",
      "set.xgbSuspicious": "XGB شکمن",
      "set.xgbSuspiciousHelp": "د معمولي خبرتیا کچه",
      "set.xgbAttack": "XGB برید",
      "set.xgbAttackHelp": "د معمولي کلک بندیز کچه",
      "set.transformer": "ټرانسفارمر",
      "set.transformerHelp": "د لړۍ د برید کچه",
      "set.autoencoder": "آټو‌انکوډر",
      "set.autoencoderHelp": "د بیا‌جوړونې د تېروتنې پوله",
      "set.policy": "د مخنیوي پالیسي",
      "set.policyHint": "غبرګون او بندول",
      "set.autoBlock": "سرغړونکي په اتوماتیک ډول بندول",
      "set.dryRun": "آزمایښتي چلول (سمولیشن)",
      "set.blockThreshold": "د N خبرتیاوو وروسته بندول",
      "set.blockDuration": "د بندیز موده (ثانیه)",
      "set.policyHelp":
        'کله چې آزمایښتي چلول ګل وي، بندیزونه ریښتیني <span class="mono">iptables -A INPUT -s &lt;ip&gt; -j DROP</span> قواعد چلوي او بیک‌اِنډ باید د root په واک سره وچلیږي.',

      "btn.close": "بندول",
      "modal.loading": "په پورته کولو کې...",
      "modal.noRecentFlows": "د دې کوربه لپاره وروستی جریان نشته.",
      "modal.loadFailed": "جریان پورته نه شو.",
      "modal.latestFeatures": "د وروستي جریان ځانګړتیاوې",
      "feat.total_packets": "پاکټونه",
      "feat.total_bytes": "بایټ",
      "feat.flow_duration": "موده (ثانیه)",
      "feat.flow_pkts_per_s": "پاکټ په ثانیه",
      "feat.down_up_ratio": "ښکته/پورته",
      "feat.syn_flag_count": "SYN",
      "feat.rst_flag_count": "RST",
      "feat.pkt_len_mean": "منځنی اوږدوالی",

      "empty.noEvents": "تر اوسه سمون‌لرونکې پېښه نشته.",
      "empty.noAlerts": "تر اوسه خبرتیا نشته.",
      "empty.noSources": "هیڅ سرچینه ونه لیدل شوه.",
      "empty.noBlocks": "هیڅ فعال بندیز نشته.",

      "status.NORMAL": "عادي",
      "status.SUSPICIOUS": "شکمن",
      "status.ATTACK": "برید",
      "status.UNKNOWN": "ناڅرګند",
      "statusPlural.NORMAL": "عادي",
      "statusPlural.SUSPICIOUS": "شکمن",
      "statusPlural.ATTACK": "بریدونه",
      "statusPlural.UNKNOWN": "ناڅرګند",

      "state.WAITING": "په انتظار",
      "state.PASS": "تېر شو",
      "state.ALERT": "خبرتیا",
      "state.UNAVAILABLE": "شتون نلري",

      "sev.critical": "بحراني",
      "sev.high": "لوړ",
      "sev.medium": "منځنی",
      "sev.low": "ټیټ",

      "mode.model": "موډل",
      "mode.surrogate": "بدیل",
      "mode.unavailable": "شتون نلري",
      "mode.heuristic": "اکتشافي",
      "route.A": "A (اکتشافي)",
      "route.B": "B (څو‌ټولګیز موډل)",

      "action.observe": "څارنه",
      "action.watch": "تر نظر لاندې",
      "action.block": "بندول",
      "action.blocked": "بند شوی",
      "action.unblock": "خلاصول",

      "atype.portscan": "د پورټ سکن",
      "atype.synflood": "د SYN سیلاب",
      "atype.udpflood": "د UDP سیلاب",
      "atype.icmpflood": "د ICMP سیلاب",
      "atype.httpflood": "د HTTP سیلاب",
      "atype.slowloris": "سلولوریس",
      "atype.dos": "د خدمت د منع برید",
      "atype.anomaly": "بې‌قاعدګي",

      "reason.transformerConfirmed": "ټرانسفارمر د جریان د لړۍ دښمنانه شالید تایید کړ.",
      "reason.transformerPartial": "ټرانسفارمر کوربه د نیمګړي (وختي) شالید له مخې په نښه کړ.",
      "reason.bothCrossed": "معمولي کټګوري‌کوونکی او د بې‌قاعدګۍ کشفوونکی دواړه د برید له پالیسۍ واوښتل.",
      "reason.xgbAttack": "د XGBoost معمولي خنډ د برید له کچې واوښت.",
      "reason.suspOutsideRecon": "جریان شکمن دی او د بیا‌جوړونې له عادي حدودو بهر دی.",
      "reason.aeOutOfOrdinary": "آټو‌انکوډر یو غیر عادي جریان وموند.",
      "reason.xgbSuspicious": "د XGBoost معمولي خنډ جریان شکمن وګاڼه.",
      "reason.noModel": "د دې جریان د ارزولو لپاره هیڅ موډل شتون نه درلود.",
      "reason.allBelow": "ټول شته خنډونه د پالیسۍ له کچو ښکته دي.",
      "reason.captureFailed": "ژوندی نیول پیل نه شو (د root واک / سم انټرفیس ته اړتیا).",
      "reason.manual": "لاسي",
      "reason.autoBlock": "اتوماتیک بندیز: {count} خبرتیاوې ≥ {threshold}",

      "msg.noSourceIp": "د سرچینې IP شتون نلري.",
      "msg.belowThreshold": "د غبرګون له کچې ښکته.",
      "msg.alreadyBlocked": "{ip} له مخکې بند دی ({count} خبرتیاوې).",
      "msg.blockRegistered": "د {ip} لپاره بندیز ثبت شو.",
      "msg.watch": "{count}/{threshold} خبرتیاوې له دې سرچینې{tail}",
      "msg.autoBlockIn": " · اتوماتیک بندیز د {n} نورو خبرتیاوو وروسته.",
      "msg.autoBlockOff": " · اتوماتیک بندیز ګل دی.",

      "toast.autoBlocked": "اتوماتیک بند شو",
      "toast.settingsSaved": "تنظیمات خوندي او دایمي شول.",
      "toast.modelsReloaded": "موډلونه بیا پورته شول.",
      "toast.blockRegistered": "د {ip} لپاره بندیز ثبت شو.",
      "toast.captureFailed": "نیول ناکام شو: {error}",
      "toast.backendOffline": "بیک‌اِنډ آفلاین دی — د Flask سرور پیل کړئ.",

      "unit.ms": "{n} ملي‌ثانیې",
      "unit.rawMse": "خام {n} MSE",
      "unit.rawProb": "خام {n} احتمال",
      "unit.mse": "{n} MSE",
      "unit.source": "سرچینه",
    },
  };

  // ------------------------------------------------------- backend text tables
  // The Flask backend emits fixed English sentences. Map each one back to a key
  // so the live feed reads in the selected locale without touching the API.
  const REASON_MAP = {
    "Transformer confirmed hostile flow-sequence context.": "reason.transformerConfirmed",
    "Transformer flagged the host on partial (early) context.": "reason.transformerPartial",
    "Routine classifier and anomaly detector both crossed attack policy.": "reason.bothCrossed",
    "Routine XGBoost barrier crossed attack threshold.": "reason.xgbAttack",
    "Flow is suspicious and outside normal reconstruction range.": "reason.suspOutsideRecon",
    "Autoencoder found an out-of-ordinary flow.": "reason.aeOutOfOrdinary",
    "Routine XGBoost barrier marked the flow suspicious.": "reason.xgbSuspicious",
    "No model was available to score this flow.": "reason.noModel",
    "All available barriers are below policy thresholds.": "reason.allBelow",
    "Live capture could not start (need root / valid interface).": "reason.captureFailed",
    "No source IP available.": "msg.noSourceIp",
    "Below response threshold.": "msg.belowThreshold",
    manual: "reason.manual",
  };

  // Parameterised backend strings, longest/most specific first.
  const PATTERNS = [
    { re: /^auto-block: (\d+) alerts ≥ (\d+)$/, key: "reason.autoBlock", args: ["count", "threshold"] },
    { re: /^Block registered for (.+)\.$/, key: "msg.blockRegistered", args: ["ip"] },
    { re: /^(.+) already blocked \((\d+) alerts\)\.$/, key: "msg.alreadyBlocked", args: ["ip", "count"] },
  ];

  // ------------------------------------------------------------------- runtime
  let current = DEFAULT_LOCALE;
  const listeners = new Set();

  function pickInitialLocale() {
    let stored = null;
    try {
      stored = localStorage.getItem(STORAGE_KEY);
    } catch (_) {
      /* private mode / storage disabled */
    }
    if (stored && STRINGS[stored]) return stored;
    const nav = (navigator.language || "").toLowerCase();
    if (nav.startsWith("ps")) return "ps";
    if (nav.startsWith("fa") || nav.startsWith("prs")) return "fa-AF";
    return DEFAULT_LOCALE;
  }

  function interpolate(template, params) {
    if (!params) return template;
    return String(template).replace(/\{(\w+)\}/g, (m, name) =>
      Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : m
    );
  }

  /** Translate `key`, substituting {placeholders} from `params`. */
  function t(key, params) {
    const table = STRINGS[current] || STRINGS[DEFAULT_LOCALE];
    const value =
      table[key] !== undefined ? table[key] : STRINGS[DEFAULT_LOCALE][key] !== undefined ? STRINGS[DEFAULT_LOCALE][key] : key;
    return interpolate(value, params);
  }

  /** True when `key` exists in any table (used to guard optional lookups). */
  function has(key) {
    return STRINGS[DEFAULT_LOCALE][key] !== undefined;
  }

  /**
   * Localise an English sentence produced by the backend. Handles the fixed
   * catalogue, the parameterised patterns, and the "watch" message whose tail
   * is itself a translatable clause. Unrecognised text passes through unchanged.
   */
  function serverText(text) {
    if (text === null || text === undefined) return "";
    const raw = String(text).trim();
    if (!raw) return "";
    if (REASON_MAP[raw]) return t(REASON_MAP[raw]);

    for (const p of PATTERNS) {
      const m = raw.match(p.re);
      if (m) {
        const params = {};
        p.args.forEach((name, i) => (params[name] = m[i + 1]));
        return t(p.key, params);
      }
    }

    // "3/5 alert(s) from source · auto-block in 2 more alert(s)."
    const watch = raw.match(/^(\d+)\/(\d+) alert\(s\) from source(.*)$/);
    if (watch) {
      let tail = watch[3] || "";
      const more = tail.match(/ · auto-block in (\d+) more alert\(s\)\./);
      if (more) tail = t("msg.autoBlockIn", { n: more[1] });
      else if (/ · auto-block off\./.test(tail)) tail = t("msg.autoBlockOff");
      return t("msg.watch", { count: watch[1], threshold: watch[2], tail });
    }
    return raw;
  }

  /** Alias kept for readability at call sites that handle decision reasons. */
  const serverReason = serverText;

  // -------------------------------------------------------- static DOM binding
  /**
   * Apply translations to every tagged node in `root`:
   *   data-i18n            → textContent
   *   data-i18n-html       → innerHTML (for strings carrying inline markup)
   *   data-i18n-placeholder→ placeholder attribute
   *   data-i18n-title      → title attribute
   */
  function applyStatic(root = document) {
    root.querySelectorAll("[data-i18n]").forEach((node) => {
      node.textContent = t(node.getAttribute("data-i18n"));
    });
    root.querySelectorAll("[data-i18n-html]").forEach((node) => {
      node.innerHTML = t(node.getAttribute("data-i18n-html"));
    });
    root.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
      node.setAttribute("placeholder", t(node.getAttribute("data-i18n-placeholder")));
    });
    root.querySelectorAll("[data-i18n-title]").forEach((node) => {
      node.setAttribute("title", t(node.getAttribute("data-i18n-title")));
    });
    if (root === document) document.title = t("app.title");
  }

  /**
   * Preload the active locale's primary faces. Runs from <head> before the
   * stylesheet is parsed, so the font request starts immediately rather than
   * waiting for CSS to discover the @font-face rule — that discovery delay is
   * what makes RTL text flash in a fallback face on first paint.
   */
  const preloaded = new Set();
  function preloadFonts() {
    const meta = LOCALES[current] || LOCALES[DEFAULT_LOCALE];
    (meta.preload || []).forEach((href) => {
      if (preloaded.has(href)) return;
      preloaded.add(href);
      const link = document.createElement("link");
      link.rel = "preload";
      link.as = "font";
      link.type = "font/woff2";
      link.crossOrigin = "anonymous";   // required for font preload, even same-origin
      link.href = href;
      (document.head || document.documentElement).appendChild(link);
    });
  }

  function applyDocumentDirection() {
    const meta = LOCALES[current] || LOCALES[DEFAULT_LOCALE];
    const html = document.documentElement;
    html.setAttribute("lang", current);
    html.setAttribute("dir", meta.dir);
    html.classList.toggle("rtl", meta.dir === "rtl");
    html.setAttribute("data-locale", current);
  }

  /** Switch locale, persist it, retranslate the shell and notify app.js. */
  function setLocale(locale, { silent = false } = {}) {
    if (!STRINGS[locale] || locale === current) {
      if (locale === current && !silent) notify();
      return;
    }
    current = locale;
    try {
      localStorage.setItem(STORAGE_KEY, locale);
    } catch (_) {
      /* ignore */
    }
    applyDocumentDirection();
    preloadFonts();
    applyStatic();
    syncSwitcher();
    if (!silent) notify();
  }

  function notify() {
    listeners.forEach((fn) => {
      try {
        fn(current);
      } catch (err) {
        console.error(err);
      }
    });
  }

  function onChange(fn) {
    listeners.add(fn);
  }

  function syncSwitcher() {
    document.querySelectorAll("[data-lang-switcher]").forEach((sel) => {
      if (sel.value !== current) sel.value = current;
    });
    document.querySelectorAll("[data-lang-option]").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-lang-option") === current);
      btn.setAttribute("aria-pressed", String(btn.getAttribute("data-lang-option") === current));
    });
  }

  /** Wire any `[data-lang-switcher]` <select> and `[data-lang-option]` button. */
  function mountSwitcher() {
    document.querySelectorAll("[data-lang-switcher]").forEach((sel) => {
      if (sel.dataset.mounted === "1") return;
      sel.dataset.mounted = "1";
      if (!sel.options.length) {
        Object.entries(LOCALES).forEach(([code, meta]) => {
          const opt = document.createElement("option");
          opt.value = code;
          opt.textContent = meta.native;
          sel.appendChild(opt);
        });
      }
      sel.addEventListener("change", (e) => setLocale(e.target.value));
    });
    document.body.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-lang-option]");
      if (btn) setLocale(btn.getAttribute("data-lang-option"));
    });
    syncSwitcher();
  }

  // This script runs in <head>: settle direction, fonts and the tab title before
  // first paint so an RTL user never sees an LTR/English/fallback-font flash.
  current = pickInitialLocale();
  applyDocumentDirection();
  preloadFonts();
  document.title = t("app.title");

  window.I18N = {
    t,
    has,
    serverText,
    serverReason,
    applyStatic,
    setLocale,
    onChange,
    mountSwitcher,
    syncSwitcher,
    locales: LOCALES,
    get locale() {
      return current;
    },
    get dir() {
      return (LOCALES[current] || LOCALES[DEFAULT_LOCALE]).dir;
    },
  };
})();
