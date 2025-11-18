from flask import Flask, render_template, jsonify
import socket

app = Flask(__name__)

# --- Example route: returns dummy top high-risk IOCs ---
@app.route("/api/high_risk")
def high_risk_iocs():
    # Example static data; replace with actual IOC data later
    data = [
        {"value": "46.161.50.108", "score": 85, "risk_bucket": "high"},
        {"value": "95.215.0.144", "score": 85, "risk_bucket": "high"},
        {"value": "31.47.55.132", "score": 84, "risk_bucket": "high"},
    ]
    return jsonify(data)

# --- Dashboard homepage ---
@app.route("/")
def index():
    return """
    <html>
    <head>
        <title>OSINT Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #2c3e50; }
            table { border-collapse: collapse; width: 60%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            tr:hover { background-color: #f5f5f5; }
        </style>
    </head>
    <body>
        <h1>High-Risk IOCs Dashboard</h1>
        <table id="ioc-table">
            <tr><th>Value</th><th>Score</th><th>Risk Bucket</th></tr>
        </table>
        <script>
            fetch('/api/high_risk')
                .then(resp => resp.json())
                .then(data => {
                    const table = document.getElementById('ioc-table');
                    data.forEach(ioc => {
                        const row = table.insertRow();
                        row.insertCell(0).innerText = ioc.value;
                        row.insertCell(1).innerText = ioc.score;
                        row.insertCell(2).innerText = ioc.risk_bucket;
                    });
                });
        </script>
    </body>
    </html>
    """

# --- Utility: find free port ---
def find_free_port(start=5000, end=5010):
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free ports available in range {start}-{end}")

# --- Main ---
if __name__ == "__main__":
    port = find_free_port()
    print(f"Starting dashboard on http://127.0.0.1:{port} (CTRL-C to quit)")
    app.run(host="127.0.0.1", port=port, debug=True)
