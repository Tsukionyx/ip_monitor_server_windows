from collections import Counter
from datetime import datetime
import threading

from flask import Flask, jsonify, render_template_string, request

from scapy.arch.windows import get_windows_if_list

from capture import PacketSniffer


app = Flask(__name__)


# =========================================================
# グローバル状態
# =========================================================

sniffer_thread = None
stop_event = threading.Event()

packet_counts = Counter()
total_packets = 0

last_error = None

lock = threading.Lock()


# =========================================================
# HTML
# =========================================================

HTML = """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>IP Traffic Monitor</title>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f5f5f5;
        }

        h1 {
            margin-bottom: 20px;
        }

        .panel {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }

        select,
        input,
        button {
            padding: 8px;
            margin-right: 5px;
        }

        button {
            cursor: pointer;
        }

        .status {
            margin-top: 15px;
            font-weight: bold;
        }

        .stats {
            display: flex;
            gap: 30px;
            margin-bottom: 20px;
        }

        .stat {
            font-size: 18px;
        }

        .chart-container {
            position: relative;
            height: 450px;
        }

        .error {
            color: red;
            margin-top: 10px;
        }
    </style>
</head>

<body>

<h1>IP Traffic Monitor</h1>

<div class="panel">

    <h2>Capture</h2>

    <label>
        Interface:
        <select id="interface">
            <option value="">読み込み中...</option>
        </select>
    </label>

    <br><br>

    <label>
        BPF Filter:
        <input
            type="text"
            id="filter"
            placeholder="例: tcp"
            value=""
        >
    </label>

    <br><br>

    <button onclick="startCapture()">Start</button>
    <button onclick="stopCapture()">Stop</button>
    <button onclick="resetCounts()">Reset</button>

    <div class="status">
        Status:
        <span id="status">Stopped</span>
    </div>

    <div id="error" class="error"></div>

</div>


<div class="panel">

    <div class="stats">

        <div class="stat">
            Total:
            <strong id="total">0</strong>
        </div>

        <div class="stat">
            Unique IP:
            <strong id="unique">0</strong>
        </div>

    </div>

    <div class="chart-container">
        <canvas id="trafficChart"></canvas>
    </div>

</div>


<script>

let chart = null;


// =========================================================
// Chart
// =========================================================

function createChart() {

    const ctx = document
        .getElementById("trafficChart")
        .getContext("2d");

    chart = new Chart(ctx, {

        type: "bar",

        data: {
            labels: [],
            datasets: [{
                label: "Packet Count",
                data: []
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }

    });
}


// =========================================================
// Interface
// =========================================================

async function loadInterfaces() {

    const response = await fetch("/api/interfaces");
    const data = await response.json();

    const select = document.getElementById("interface");

    select.innerHTML = "";

    for (const iface of data.interfaces) {

        const option = document.createElement("option");

        option.value = iface.value;
        option.textContent = iface.name;

        select.appendChild(option);
    }
}


// =========================================================
// Start
// =========================================================

async function startCapture() {

    const iface = document.getElementById("interface").value;
    const filter = document.getElementById("filter").value;

    const response = await fetch("/api/start", {

        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify({
            interface: iface,
            filter: filter
        })
    });

    const data = await response.json();

    document.getElementById("status").textContent = data.status;
}


// =========================================================
// Stop
// =========================================================

async function stopCapture() {

    const response = await fetch("/api/stop", {
        method: "POST"
    });

    const data = await response.json();

    document.getElementById("status").textContent = data.status;
}


// =========================================================
// Reset
// =========================================================

async function resetCounts() {

    await fetch("/api/reset", {
        method: "POST"
    });
}


// =========================================================
// Statistics
// =========================================================

async function updateStats() {

    try {

        const response = await fetch("/api/stats");
        const data = await response.json();

        document.getElementById("total").textContent =
            data.total;

        document.getElementById("unique").textContent =
            data.unique;

        document.getElementById("status").textContent =
            data.running ? "Running" : "Stopped";

        if (data.error) {
            document.getElementById("error").textContent =
                data.error;
        }

        chart.data.labels = data.top.map(item => item.ip);

        chart.data.datasets[0].data =
            data.top.map(item => item.count);

        chart.update();

    } catch (error) {

        console.error(error);
    }
}


// =========================================================
// Initialization
// =========================================================

createChart();

loadInterfaces();

setInterval(updateStats, 1000);

updateStats();

</script>

</body>
</html>
"""


# =========================================================
# Packet callback
# =========================================================

def on_packet(packet_info):
    global total_packets
    global last_error

    if packet_info.get("type") == "error":
        last_error = packet_info.get("message")
        return

    src_ip = packet_info["src_ip"]

    with lock:
        packet_counts[src_ip] += 1
        total_packets += 1


# =========================================================
# Routes
# =========================================================

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/interfaces")
def interfaces():

    result = []

    try:

        interfaces = get_windows_if_list()

        for iface in interfaces:

            name = iface.get("name", "")
            value = iface.get("name", "")

            result.append({
                "name": name,
                "value": value,
            })

    except Exception as e:

        return jsonify({
            "interfaces": [],
            "error": str(e)
        }), 500

    return jsonify({
        "interfaces": result
    })


@app.route("/api/start", methods=["POST"])
def start():

    global sniffer_thread
    global stop_event
    global last_error

    data = request.get_json() or {}

    iface = data.get("interface")
    bpf_filter = data.get("filter", "")

    if not iface:
        return jsonify({
            "status": "No interface selected"
        }), 400

    # 既に動作中なら何もしない
    if sniffer_thread is not None and sniffer_thread.is_alive():
        return jsonify({
            "status": "Already running"
        })

    last_error = None

    stop_event = threading.Event()

    sniffer_thread = PacketSniffer(
        iface_name=iface,
        packet_callback=on_packet,
        stop_event=stop_event,
        bpf_filter=bpf_filter,
    )

    sniffer_thread.start()

    return jsonify({
        "status": "Running"
    })


@app.route("/api/stop", methods=["POST"])
def stop():

    global sniffer_thread

    if sniffer_thread is not None:

        stop_event.set()

        return jsonify({
            "status": "Stopping"
        })

    return jsonify({
        "status": "Stopped"
    })


@app.route("/api/reset", methods=["POST"])
def reset():

    global total_packets
    global last_error

    with lock:

        packet_counts.clear()
        total_packets = 0
        last_error = None

    return jsonify({
        "status": "Reset"
    })


@app.route("/api/stats")
def stats():

    with lock:

        top = [
            {
                "ip": ip,
                "count": count
            }
            for ip, count
            in packet_counts.most_common(10)
        ]

        total = total_packets
        unique = len(packet_counts)

    running = (
        sniffer_thread is not None
        and sniffer_thread.is_alive()
    )

    return jsonify({
        "total": total,
        "unique": unique,
        "top": top,
        "running": running,
        "error": last_error,
    })


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True,
    )
