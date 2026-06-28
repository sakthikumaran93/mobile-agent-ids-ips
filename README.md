# Distributed Intrusion Prevention System (DIPS)

A scalable, multi-layered, and distributed network security architecture designed to protect campus-wide infrastructure (Labs, Hostels, Faculty networks) by shifting threat detection and enforcement to the network edge.

## 🚀 Key Features

* **Distributed Edge Defense:** Deploys **250+ Mobile Agents** across decentralized nodes simultaneously using automated **SSH Deployment**.
* **Triple-Threat Security Stack:** Each localized agent utilizes:
  * `libpcap` for low-level, high-efficiency raw packet capturing.
  * `Snort (80K+ Rules)` as the signature-matching detection engine.
  * `iptables` for immediate packet dropping and IP blocking at the source.
* **Lightweight Telemetry:** Localized threats are blocked and packaged into optimized **JSON Reports**.
* **Central Analytics Hub:** A centralized server (running on `localhost:8080`) aggregates real-time metrics using an embedded **SQLite** log database.
* **Live Operations Dashboard:** Includes a Web UI featuring a live node health map (e.g., tracking 247/250 online agents) and actionable attack forensics.
