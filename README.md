
# Cybersecurity Kill Chain Defense Simulation Platform

## Overview

This project is an interactive **cybersecurity defense simulation and SOC-style dashboard** focused on analyzing, detecting, and responding to **phishing attacks**.

The platform visualizes how an attack progresses across the **MITRE ATT&CK / cyber kill chain**, evaluates the effectiveness of deployed security controls, and provides **actionable incident response guidance** for defenders. Rather than generating isolated alerts, the system highlights **where defenses succeed, where they fail, and why**.

The project is designed for **blue team operations, security training, capability assessment, and defensive research**.

<img width="1918" height="771" alt="image" src="https://github.com/user-attachments/assets/99dc84d1-5f60-476a-934e-04a6d007b761" />




---

## Key Features

### 🛡️ Threat Detection Overview

* Displays the **active threat type** (e.g. Phishing)
* Calculates an **overall detection success rate**
* Provides immediate visibility into defensive coverage gaps

This allows defenders to quickly assess whether current controls are effectively mitigating the attack.

---

### 🔍 Technical Trace Analysis (Kill Chain Mapping)

The platform breaks attacks into distinct stages:

* Reconnaissance
* Delivery
* Exploitation
* Installation
* Command & Control
* Actions on Objectives

For each stage, it shows:

* Detection status (Detected / Missed)
* The security control involved (Firewall, IDS, Email Gateway, Endpoint Security, SIEM, etc.)
* Technical details explaining **successes or failures** (e.g. misconfiguration, encrypted traffic evasion, insufficient log correlation)

This transforms alerts into **structured post-incident intelligence**.

---

### 🚨 Incident Response Playbooks

Integrated **blue team incident response playbooks** are dynamically tied to the active threat.

Includes:

* Estimated response time
* Step-by-step response actions
* Practical mitigation guidance focused on real SOC workflows

This feature supports both **live response** and **training/tabletop exercises**.

---

### 🎯 Attacker Behavior & Objectives

The dashboard models likely **attacker actions and objectives**, such as:

* Mass phishing campaigns
* Credential harvesting
* Persistence establishment

This perspective helps defenders anticipate next steps and prioritize defensive actions.

---

### 💡 Defensive Capability & Tooling Simulation

The platform supports modular defensive controls (e.g. Intrusion Prevention Systems, API Security Gateways), allowing users to:

* Assess how tooling impacts detection coverage
* Identify weak points in security architecture
* Explore defensive investment trade-offs

This makes the project well-suited for **strategy evaluation and capability planning**.

---

## Intended Use Cases

* Security Operations Center (SOC) analysis
* Blue team training and exercises
* Cybersecurity education
* Defensive tooling research
* Security capability assessment

---

## Disclaimer

This project is intended for **defensive and educational purposes only**. It does not provide offensive tooling or exploit code.

---

## Status

Active development. Features, scenarios, and playbooks are continuously evolving.

---

## Running with Docker

### Prerequisites

* [Docker](https://www.docker.com/get-started) installed on your machine

### Start the app

```bash
git clone https://github.com/MoriartyPuth/Cyber-kill-chain-tool.git
cd Cyber-kill-chain-tool
docker-compose up --build
```

Then open your browser at `http://localhost:5000`

### Stop the app

```bash
docker-compose down
```

### Configuration

Environment variables can be set in `docker-compose.yml`:

| Variable | Default | Description |
| --- | --- | --- |
| `SECRET_KEY` | `change-this-...` | Flask session secret — change before deploying |
| `DATABASE_URL` | `sqlite:///cyber_killchain.db` | Database connection string |
| `INITIAL_BUDGET` | `5000` | Starting defense budget |
| `FLASK_ENV` | `production` | Flask environment |
| `OPENAI_API_KEY` | _(empty)_ | Optional — enables AI-powered threat analysis |

> The SQLite database is persisted in a Docker volume (`db_data`) so data survives container restarts.
