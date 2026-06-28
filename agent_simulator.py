"""
agent_simulator.py
==================
Local backend server for the NeuroIDS Dashboard (ids_dashboard.html).

Architecture:
  - 250 virtual agents run in background threads, each detecting threats
  - A lightweight HTTP server (no dependencies beyond stdlib + requests)
    exposes two endpoints:
      GET  /events        → returns JSON array of latest threat events (polled by dashboard)
      GET  /stats         → returns aggregate stats (agents, packets, latency)
      POST /report        → agents POST their detections here
      GET  /              → serves the dashboard HTML file directly
  - The dashboard polls /events every 1.5 s via fetch() to display live data

Run:
  pip install requests        # only external dep (for agent->server POST)
  python agent_simulator.py

Then open:  http://localhost:8080
"""

import threading
import time
import random
import json
import queue
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque
from pathlib import Path

# ──────────────────────────────────────────────
#  CONFIG
# ──────────────────────────────────────────────
PORT          = 8080
NUM_AGENTS    = 250
ATTACK_RATE   = 0.25          # probability any tick produces an attack
TICK_MIN      = 0.8           # seconds – fastest agent tick
TICK_MAX      = 3.0           # seconds – slowest agent tick
MAX_EVENTS    = 500           # ring-buffer size for /events
DASHBOARD_FILE = "ids_dashboard.html"   # served at GET /

# ──────────────────────────────────────────────
#  ATTACK CATALOGUE  (mirrors the JS side)
# ──────────────────────────────────────────────
ATTACKS = [
    {"id": "nmap_syn_scan",   "label": "NMAP SYN SCAN",   "severity": "medium"},
    {"id": "ssh_brute_force", "label": "SSH BRUTE FORCE",  "severity": "high"},
    {"id": "ddos_flood",      "label": "DDOS FLOOD",       "severity": "critical"},
    {"id": "sql_injection",   "label": "SQL INJECTION",    "severity": "critical"},
    {"id": "xss_attack",      "label": "XSS ATTACK",       "severity": "high"},
    {"id": "arp_poison",      "label": "ARP POISONING",    "severity": "low"},
]

IP_PREFIXES = ["10", "172", "192"]

# ──────────────────────────────────────────────
#  SHARED STATE  (thread-safe)
# ──────────────────────────────────────────────
event_buffer: deque = deque(maxlen=MAX_EVENTS)
event_lock   = threading.Lock()
event_id_counter = 0

stats = {
    "agents_total":  NUM_AGENTS,
    "agents_online": NUM_AGENTS,
    "threats_total": 0,
    "packets_total": 0,
    "packets_per_sec": 0,
    "avg_latency_ms": 0.2,
    "attack_counts": {a["id"]: 0 for a in ATTACKS},
}
stats_lock = threading.Lock()


def new_event_id() -> int:
    global event_id_counter
    event_id_counter += 1
    return event_id_counter


def random_ip() -> str:
    prefix = random.choice(IP_PREFIXES)
    return f"{prefix}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


# ──────────────────────────────────────────────
#  AGENT CLASS
# ──────────────────────────────────────────────
class Agent:
    """
    Simulates one mobile IDS agent.
    Each agent runs in its own daemon thread, processes virtual packets,
    and POSTs detected threats directly into the shared state (no HTTP
    overhead since we're in the same process).
    """

    def __init__(self, agent_id: int):
        self.agent_id   = agent_id
        self.label      = f"AGENT-{agent_id:03d}"
        self.zone       = f"192.168.{(agent_id - 1) // 50}.0/24"
        self.rule_count = random.randint(75_000, 82_000)
        self.blocked    = 0
        self.packets    = 0

    def run(self):
        while True:
            tick = random.uniform(TICK_MIN, TICK_MAX)
            time.sleep(tick)

            # Packet throughput contribution
            pkt = random.randint(20, 80)
            self.packets += pkt
            with stats_lock:
                stats["packets_total"] += pkt

            # Maybe detect a threat
            if random.random() < ATTACK_RATE:
                self._detect_and_report()

    def _detect_and_report(self):
        atk      = random.choice(ATTACKS)
        src_ip   = random_ip()
        latency  = round(random.uniform(0.10, 0.55), 2)
        dropped  = random.randint(50, 12_000)
        sid      = random.randint(10_000, 99_999)
        now      = time.strftime("%H:%M:%S")
        full_ts  = time.strftime("%Y-%m-%d %H:%M:%S")

        event = {
            "id":        new_event_id(),
            "time":      now,
            "fullTime":  full_ts,
            "agent":     self.label,
            "agentId":   self.agent_id,
            "zone":      self.zone,
            "attack":    atk["id"].upper().replace("_", " "),
            "attackId":  atk["id"],
            "severity":  atk["severity"],
            "ip":        src_ip,
            "sid":       sid,
            "dropped":   dropped,
            "latency":   latency,
            "action":    "BLOCKED",
        }

        self.blocked += 1

        with event_lock:
            event_buffer.appendleft(event)

        with stats_lock:
            stats["threats_total"] += 1
            stats["attack_counts"][atk["id"]] += 1
            # Rolling average latency (exponential moving average)
            stats["avg_latency_ms"] = round(
                stats["avg_latency_ms"] * 0.95 + latency * 0.05, 3
            )

        # Console output (throttled – only for first 10 agents to avoid spam)
        if self.agent_id <= 10:
            print(f"[{now}] {self.label} | BLOCKED {atk['id']:20s} from {src_ip}  ({latency}ms)")


# ──────────────────────────────────────────────
#  PACKETS-PER-SECOND CALCULATOR
# ──────────────────────────────────────────────
def _pps_calculator():
    """Updates stats['packets_per_sec'] every second."""
    last = 0
    while True:
        time.sleep(1)
        with stats_lock:
            current = stats["packets_total"]
            stats["packets_per_sec"] = current - last
            last = current


# ──────────────────────────────────────────────
#  HTTP REQUEST HANDLER
# ──────────────────────────────────────────────
class IDSHandler(BaseHTTPRequestHandler):

    # ── Silence the default access log ──────────────────────────────────
    def log_message(self, fmt, *args):
        pass   # comment this out if you want per-request logs

    # ── CORS helper ─────────────────────────────────────────────────────
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    # ── JSON response helper ─────────────────────────────────────────────
    def _json(self, data: dict | list, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    # ── OPTIONS (preflight) ──────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    # ── GET ──────────────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0]

        # Serve dashboard HTML
        if path in ("/", "/index.html", f"/{DASHBOARD_FILE}"):
            html_path = Path(DASHBOARD_FILE)
            if html_path.exists():
                content = html_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Dashboard HTML not found. Place ids_dashboard.html here.")
            return

        # Latest events (dashboard polls this)
        if path == "/events":
            with event_lock:
                data = list(event_buffer)   # newest first
            self._json(data)
            return

        # Aggregate stats
        if path == "/stats":
            with stats_lock:
                data = dict(stats)
            self._json(data)
            return

        self.send_response(404)
        self.end_headers()

    # ── POST ─────────────────────────────────────────────────────────────
    def do_POST(self):
        """
        Accepts external agent reports (e.g. from real Snort/Suricata hooks).
        Body: { agent, threat, src_ip, timestamp, action }
        """
        if self.path != "/report":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        try:
            payload  = json.loads(body)
            atk_id   = payload.get("threat", "unknown")
            severity = next((a["severity"] for a in ATTACKS if a["id"] == atk_id), "medium")

            event = {
                "id":       new_event_id(),
                "time":     payload.get("timestamp", time.strftime("%H:%M:%S")),
                "fullTime": time.strftime("%Y-%m-%d %H:%M:%S"),
                "agent":    payload.get("agent", "EXTERNAL"),
                "agentId":  0,
                "zone":     "external",
                "attack":   atk_id.upper().replace("_", " "),
                "attackId": atk_id,
                "severity": severity,
                "ip":       payload.get("src_ip", "0.0.0.0"),
                "sid":      random.randint(10_000, 99_999),
                "dropped":  random.randint(1, 500),
                "latency":  round(random.uniform(0.1, 0.5), 2),
                "action":   payload.get("action", "BLOCKED"),
            }

            with event_lock:
                event_buffer.appendleft(event)
            with stats_lock:
                stats["threats_total"] += 1
                if atk_id in stats["attack_counts"]:
                    stats["attack_counts"][atk_id] += 1

            self._json({"status": "ok", "id": event["id"]}, 201)

        except (json.JSONDecodeError, KeyError) as exc:
            self._json({"error": str(exc)}, 400)


# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  NeuroIDS Agent Simulator")
    print("=" * 60)
    print(f"  Spawning {NUM_AGENTS} agents …")

    # Start agents
    agents = [Agent(i) for i in range(1, NUM_AGENTS + 1)]
    for agent in agents:
        t = threading.Thread(target=agent.run, daemon=True)
        t.start()

    # Start PPS calculator
    threading.Thread(target=_pps_calculator, daemon=True).start()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", PORT), IDSHandler)
    print(f"  HTTP server listening on http://localhost:{PORT}")
    print(f"  Dashboard  → http://localhost:{PORT}/")
    print(f"  Events API → http://localhost:{PORT}/events")
    print(f"  Stats API  → http://localhost:{PORT}/stats")
    print(f"  Report API → POST http://localhost:{PORT}/report")
    print("=" * 60)
    print("  Console shows activity from AGENT-001 … AGENT-010 only.")
    print("  Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        total = sum(a.blocked for a in agents)
        print(f"\n  Stopped. Total threats blocked this session: {total:,}")


if __name__ == "__main__":
    main()
