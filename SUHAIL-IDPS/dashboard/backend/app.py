import os
import sys

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

sys.path.append(PROJECT_ROOT)


from flask import Flask, jsonify, request
from flask_cors import CORS
import time
from collections import deque


from src.core.decision_engine import analyze_packet

app = Flask(__name__)
CORS(app)

# =========================
# STORAGE (LIVE DATA)
# =========================
logs = deque(maxlen=200)
stats = {
    "total": 0,
    "normal": 0,
    "suspicious": 0,
    "attacks": 0
}


# =========================
# MAIN IDS ENDPOINT
# =========================
@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.json

    packet = data["packet"]
    sequence = data.get("sequence", None)

    result = analyze_packet(packet, sequence)

    stats["total"] += 1

    if result["status"] == "NORMAL":
        stats["normal"] += 1
    elif result["status"] == "SUSPICIOUS":
        stats["suspicious"] += 1
    else:
        stats["attacks"] += 1

    logs.append({
        "time": time.time(),
        "result": result
    })

    return jsonify(result)


# =========================
# STATS ENDPOINT
# =========================
@app.route("/stats")
def get_stats():
    return jsonify(stats)


# =========================
# LIVE LOGS
# =========================
@app.route("/logs")
def get_logs():
    return jsonify(list(logs))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
