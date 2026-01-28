import socket
from flask import Flask, jsonify, request, render_template
from pathlib import Path
import json

app = Flask(__name__)

STORE_INDEX = Path("./store/iocs_indexed.json")


def find_free_port(start_port=5000, max_port=5100):
    """Find an available port."""
    for port in range(start_port, max_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("", port))
                return port
            except OSError:
                continue
    return None


def load_iocs():
    if not STORE_INDEX.exists():
        return []
    with open(STORE_INDEX) as f:
        return json.load(f)


@app.route("/api/iocs")
def api_iocs():
    """Return filtered and sorted IOCs."""
    risk_filter = request.args.get("risk", "all").lower()
    iocs = load_iocs()
    # Filter by risk_bucket if not "all"
    if risk_filter != "all":
        iocs = [i for i in iocs if i.get("risk_bucket", "").lower() == risk_filter]

    # Sort by score descending
    iocs_sorted = sorted(iocs, key=lambda x: x.get("score", 0), reverse=True)
    return jsonify(iocs_sorted)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    port = find_free_port(5000)
    if port is None:
        raise RuntimeError("No free port found between 5000-5100")
    print(f"Starting dashboard on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)