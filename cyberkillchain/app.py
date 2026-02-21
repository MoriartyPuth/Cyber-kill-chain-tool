from flask import Flask, render_template, request, session, redirect, url_for, Response, jsonify, flash, send_from_directory
import random
from datetime import datetime, timedelta
import json
import os
import base64
import urllib.request
import urllib.error
import hashlib
import ipaddress
import uuid
from collections import Counter, deque
from functools import wraps
from dotenv import load_dotenv
from sqlalchemy import text, or_
from werkzeug.utils import secure_filename
from models import db, User, Simulation, UpgradePurchase, AnalyticsReport, AIInsight, SavedSearch, SimulationPreset, SimulationSchedule, Case, CaseNote, CaseAttachment, CaseEvent, CaseChecklistItem, AuditLog, RetentionPolicy, ThreatSignature, ThreatDiscovery, ThreatSummary, ThreatAdvisory, ThreatSettings, UserWidget, Indicator, IndicatorRelation, AlertRule, LiveFilter, LiveLog, FeatureModuleSetting
from ai_advisor import AISecurityAdvisor
from flask_socketio import SocketIO

received_logs = []
LIVE_EVENTS = deque(maxlen=200)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'cyber_security_simulation_secret_2026')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cyber_killchain.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Optional background scheduler
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    APSCHEDULER_AVAILABLE = True
except Exception:
    APSCHEDULER_AVAILABLE = False

# Optional Elasticsearch configuration
ES_URL = os.getenv('ELASTICSEARCH_URL')
ES_USER = os.getenv('ELASTICSEARCH_USERNAME')
ES_PASS = os.getenv('ELASTICSEARCH_PASSWORD')
ES_API_KEY = os.getenv('ELASTICSEARCH_API_KEY')
ES_LOG_INDEX = os.getenv('ELASTICSEARCH_LOG_INDEX', 'cyberkill-logs')
ES_SIM_INDEX = os.getenv('ELASTICSEARCH_SIM_INDEX', 'cyberkill-sims')

# Initialize database
db.init_app(app)

# Initialize AI advisor (optional - will warn if no API key)
try:
    ai_advisor = AISecurityAdvisor()
    AI_ENABLED = True
except ValueError:
    ai_advisor = None
    AI_ENABLED = False
    print("Warning: OpenAI API key not configured. AI features will be limited.")

# --- Configuration Data ---
attack_profiles = {
    "Phishing": 0.6,
    "Malware": 0.7,
    "Ransomware": 0.5,
    "DDoS": 0.65,
    "Supply Chain": 0.7,
    "APT": 0.75,
    "Insider Threat": 0.55
}

ATTACK_SEVERITY = {
    "Phishing": "low",
    "Malware": "medium",
    "Ransomware": "critical",
    "DDoS": "medium",
    "Supply Chain": "high",
    "APT": "high",
    "Insider Threat": "high"
}

UPGRADES = {
    "Advanced Firewall": {"cost": 1500, "boost": 0.20, "stage": "Reconnaissance", "roi": 3.2},
    "Secure Email Gateway": {"cost": 1000, "boost": 0.25, "stage": "Delivery", "roi": 2.8},
    "EDR Solution": {"cost": 2000, "boost": 0.20, "stage": "Exploitation", "roi": 2.5},
    "Next-Gen AV": {"cost": 1200, "boost": 0.15, "stage": "Installation", "roi": 2.1},
    "Network Traffic Analysis": {"cost": 1800, "boost": 0.20, "stage": "Command & Control", "roi": 2.9},
    "SIEM Optimization": {"cost": 2500, "boost": 0.30, "stage": "Actions on Objectives", "roi": 3.5},
    "Security Awareness Training": {"cost": 800, "boost": 0.18, "stage": "Delivery", "roi": 4.2},
    "DLP Solution": {"cost": 2200, "boost": 0.25, "stage": "Actions on Objectives", "roi": 3.1},
    "Intrusion Prevention System": {"cost": 1600, "boost": 0.22, "stage": "Exploitation", "roi": 2.7},
    "API Security Gateway": {"cost": 1900, "boost": 0.23, "stage": "Command & Control", "roi": 2.6}
}

kill_chain_data = [
    ("Reconnaissance", "Firewall / IDS", ["Port scanning detected", "Suspicious IP activity"], ["Firewall misconfiguration", "Low IDS sensitivity"]),
    ("Delivery", "Email Gateway", ["Phishing email blocked", "Malicious attachment detected"], ["User clicked malicious email", "Email filter bypassed"]),
    ("Exploitation", "Endpoint Security", ["Exploit attempt blocked", "Abnormal behavior detected"], ["Zero-day vulnerability", "Outdated patches"]),
    ("Installation", "Antivirus", ["Malware installation blocked", "Unauthorized file detected"], ["Antivirus signatures outdated", "Privilege misuse"]),
    ("Command & Control", "Network Monitor", ["Suspicious outbound traffic detected", "C2 traffic blocked"], ["Encrypted traffic evaded detection", "DNS monitoring disabled"]),
    ("Actions on Objectives", "SIEM", ["Data exfiltration detected", "Privilege escalation alert"], ["Insufficient log correlation", "Delayed incident response"])
]

MITRE_ATTACK_MAPPING = {
    "Phishing": [("TA0001", "Initial Access"), ("T1566", "Phishing")],
    "Malware": [("TA0002", "Execution"), ("T1204", "User Execution")],
    "Ransomware": [("TA0040", "Impact"), ("T1486", "Data Encrypted for Impact")],
    "DDoS": [("TA0040", "Impact"), ("T1499", "Endpoint Denial of Service")],
    "Supply Chain": [("TA0001", "Initial Access"), ("T1195", "Supply Chain Compromise")],
    "APT": [("TA0008", "Lateral Movement"), ("T1021", "Remote Services")],
    "Insider Threat": [("TA0009", "Collection"), ("T1005", "Data from Local System")]
}

recommendations_map = {
    "Reconnaissance": {"improve": "Strengthen firewall rules and enable IDS anomaly detection.", "response": "Block scanning IPs and increase monitoring."},
    "Delivery": {"improve": "Improve email filtering and user awareness training.", "response": "Isolate affected accounts and scan mailboxes."},
    "Exploitation": {"improve": "Apply security patches and enable exploit protection.", "response": "Inspect systems and terminate malicious processes."},
    "Installation": {"improve": "Enable real-time antivirus and restrict admin rights.", "response": "Quarantine infected hosts and remove malware."},
    "Command & Control": {"improve": "Monitor outbound traffic and block malicious domains.", "response": "Disconnect infected systems and block C2 traffic."},
    "Actions on Objectives": {"improve": "Implement DLP and improve SIEM correlation.", "response": "Contain breach and initiate incident response."}
}

# --- Incident Response Playbooks (Feature 8) ---
incident_playbooks = {
    "Phishing": {
        "blue_team": ["Isolate affected users", "Block phishing URLs", "Scan for email forwarding rules", "Reset compromised credentials"],
        "blue_team_time": "15-30 minutes",
        "red_team": ["Send mass email campaign", "Harvest credentials from victims", "Establish persistence", "Exfiltrate data"]
    },
    "Malware": {
        "blue_team": ["Isolate infected systems", "Collect forensic data", "Remove malware", "Restore from clean backups"],
        "blue_team_time": "1-4 hours",
        "red_team": ["Execute payload", "Disable security software", "Establish C2 communication", "Lateral movement"]
    },
    "Ransomware": {
        "blue_team": ["Disconnect from network immediately", "Preserve evidence", "Restore from backups", "Negotiate if necessary"],
        "blue_team_time": "2-8 hours",
        "red_team": ["Encrypt all files", "Demand ransom", "Threaten data exposure", "Exfiltrate sensitive data"]
    },
    "DDoS": {
        "blue_team": ["Activate DDoS mitigation", "Redirect traffic", "Block malicious IPs", "Increase bandwidth"],
        "blue_team_time": "5-30 minutes",
        "red_team": ["Launch botnet attacks", "Overwhelm infrastructure", "Target key services", "Sustain attack"]
    },
    "Supply Chain": {
        "blue_team": ["Audit vendor access", "Review log files", "Check software integrity", "Update all dependencies"],
        "blue_team_time": "4-48 hours",
        "red_team": ["Compromise vendor software", "Inject backdoors", "Distribute to targets", "Maintain stealth"]
    },
    "APT": {
        "blue_team": ["Hunt for indicators", "Analyze attack patterns", "Engage threat intel", "Implement countermeasures"],
        "blue_team_time": "Hours to days",
        "red_team": ["Establish foothold", "Move laterally", "Steal intellectual property", "Maintain long-term access"]
    },
    "Insider Threat": {
        "blue_team": ["Review privileged access", "Monitor data transfers", "Check for policy violations", "Interview stakeholders"],
        "blue_team_time": "Hours to weeks",
        "red_team": ["Access sensitive systems", "Copy proprietary data", "Cover tracks", "Establish deadrop"]
    }
}

CASE_TEMPLATES = {
    "Phishing": {
        "title": "Phishing Investigation",
        "description": "Investigate reported phishing activity. Validate sender, analyze headers, and identify affected users.",
        "severity": "Medium",
        "sla_hours": 24
    },
    "Malware": {
        "title": "Malware Containment",
        "description": "Contain suspected malware, collect indicators, and isolate impacted hosts.",
        "severity": "High",
        "sla_hours": 24
    },
    "Ransomware": {
        "title": "Ransomware Response",
        "description": "Initiate ransomware response. Isolate systems, preserve evidence, and assess backups.",
        "severity": "Critical",
        "sla_hours": 8
    },
    "DDoS": {
        "title": "DDoS Mitigation",
        "description": "Mitigate denial-of-service traffic and coordinate with upstream providers.",
        "severity": "High",
        "sla_hours": 12
    },
    "Supply Chain": {
        "title": "Supply Chain Exposure",
        "description": "Assess vendor compromise impact and verify software integrity across environments.",
        "severity": "High",
        "sla_hours": 48
    },
    "APT": {
        "title": "APT Investigation",
        "description": "Conduct threat hunt for advanced persistent activity, lateral movement, and exfiltration.",
        "severity": "High",
        "sla_hours": 48
    },
    "Insider Threat": {
        "title": "Insider Threat Review",
        "description": "Review privileged access and data movement. Interview stakeholders as needed.",
        "severity": "High",
        "sla_hours": 72
    }
}

COMPLIANCE_CHECKLISTS = {
    "NIST": [
        "Identify affected assets and scope",
        "Contain the incident",
        "Preserve evidence",
        "Eradicate root cause",
        "Recover systems and verify",
        "Post-incident review"
    ],
    "ISO": [
        "Record incident details",
        "Assign incident owner",
        "Assess business impact",
        "Implement corrective actions",
        "Verify controls effectiveness",
        "Close and archive incident"
    ]
}

def get_simulation(attack_type, variant="standard"):
    """Run a simulation for the given attack type"""
    events = []
    detected_count = 0
    base_prob = attack_profiles[attack_type]
    variant = (variant or "standard").lower()
    if variant == "stealthy":
        base_prob = max(0.35, base_prob - 0.15)
    elif variant == "noisy":
        base_prob = min(0.95, base_prob + 0.1)
    elif variant == "fast":
        base_prob = max(0.4, base_prob - 0.08)
    elif variant == "slow":
        base_prob = min(0.95, base_prob + 0.05)
    upgrades = session.get('upgrades', {})

    for stage, tool, d_reasons, m_reasons in kill_chain_data:
        boost = upgrades.get(stage, 0.0)
        final_prob = min(base_prob + boost, 0.98)

        detected = random.random() < final_prob
        status = "Detected" if detected else "Missed"
        if detected:
            detected_count += 1
            reason, miss = random.choice(d_reasons), "—"
        else:
            reason, miss = "Detection failed", random.choice(m_reasons)

        events.append({
            "stage": stage, "status": status, "tool": tool,
            "reason": reason, "miss_reason": miss, "time": datetime.now().strftime("%H:%M:%S")
        })

    score = int((detected_count / len(kill_chain_data)) * 100)
    weakest = [e["stage"] for e in events if e["status"] == "Missed"]
    recs = [{"stage": s, **recommendations_map[s]} for s in weakest]
    return events, score, weakest, recs

def get_simulation_with_upgrades(attack_type, upgrades, variant="standard"):
    """Run a simulation using provided upgrades (no session dependency)."""
    events = []
    detected_count = 0
    base_prob = attack_profiles[attack_type]
    variant = (variant or "standard").lower()
    if variant == "stealthy":
        base_prob = max(0.35, base_prob - 0.15)
    elif variant == "noisy":
        base_prob = min(0.95, base_prob + 0.1)
    elif variant == "fast":
        base_prob = max(0.4, base_prob - 0.08)
    elif variant == "slow":
        base_prob = min(0.95, base_prob + 0.05)

    for stage, tool, d_reasons, m_reasons in kill_chain_data:
        boost = upgrades.get(stage, 0.0)
        final_prob = min(base_prob + boost, 0.98)

        detected = random.random() < final_prob
        status = "Detected" if detected else "Missed"
        if detected:
            detected_count += 1
            reason, miss = random.choice(d_reasons), "—"
        else:
            reason, miss = "Detection failed", random.choice(m_reasons)

        events.append({
            "stage": stage, "status": status, "tool": tool,
            "reason": reason, "miss_reason": miss, "time": datetime.now().strftime("%H:%M:%S")
        })

    score = int((detected_count / len(kill_chain_data)) * 100)
    weakest = [e["stage"] for e in events if e["status"] == "Missed"]
    recs = [{"stage": s, **recommendations_map[s]} for s in weakest]
    return events, score, weakest, recs

def _parse_event_time(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M")
        except Exception:
            return None

def _is_live_simulation(sim):
    variant = (getattr(sim, "variant", "") or "").strip().lower()
    if variant == "live":
        return True
    tags = getattr(sim, "tags", None)
    if isinstance(tags, list) and "live_log" in tags:
        return True
    if isinstance(tags, dict) and tags.get("source") == "live_log":
        return True
    return False

def _extract_event_id(events):
    if not isinstance(events, list):
        return None
    for e in events:
        if isinstance(e, dict) and e.get("event_id"):
            return e.get("event_id")
    return None

def _merge_history(live_history, db_history):
    if not live_history:
        return db_history
    if not db_history:
        return live_history
    live_ids = {h.get("event_id") for h in live_history if h.get("event_id")}
    merged = []
    merged.extend(live_history)
    for h in db_history:
        eid = h.get("event_id")
        if eid and eid in live_ids:
            continue
        merged.append(h)
    merged.sort(key=lambda h: _parse_event_time(h.get('_ts') or h.get('time')) or datetime.min, reverse=True)
    return merged

def _build_live_db_history(user_id=None, limit=500):
    history = []
    try:
        query = LiveLog.query
        if user_id:
            query = query.filter(or_(LiveLog.user_id == user_id, LiveLog.user_id.is_(None)))
        else:
            query = query.filter(LiveLog.user_id.is_(None))
        rows = query.order_by(LiveLog.created_at.desc()).limit(limit).all()
        for row in rows:
            event = {}
            chain_events = []
            severity = None
            if isinstance(row.payload, dict):
                payload = row.payload
                event = payload.get("event") or row.mapped_event or {}
                chain_events = payload.get("chain_events") or (_expand_chain_event(event) if event else [])
                severity = payload.get("severity") or event.get("severity")
            else:
                event = row.mapped_event or {}
                chain_events = _expand_chain_event(event) if event else []
                severity = event.get("severity")

            status = event.get("status")
            score = 100 if status == "Detected" else 0
            weakest = [e.get("stage") for e in chain_events if e.get("status") == "Missed"]
            history.append({
                'id': None,
                'attack': (row.raw_log or {}).get('attack_type') or event.get("attack_type"),
                'score': score,
                'time': row.created_at.strftime('%Y-%m-%d %H:%M') if row.created_at else '',
                'events': chain_events,
                'weakest': weakest,
                'severity': severity,
                'source': 'live',
                'event_id': event.get("event_id"),
                '_ts': row.created_at.isoformat() if row.created_at else None
            })
    except Exception as e:
        print(f"Error fetching LiveLog history: {e}")
        history = []
    return history

def _build_history(user_id=None):
    """Return a normalized list of simulation records for analytics.
    Uses DB when user is logged in; otherwise falls back to session history."""
    data_source = session.get('data_source', 'both')
    live_history = []
    if LIVE_EVENTS:
        for ev in list(LIVE_EVENTS):
            event = ev.get("event") or {}
            status = event.get("status")
            score = 100 if status == "Detected" else 0
            chain_events = ev.get("chain_events") or [event]
            weakest = [e.get("stage") for e in chain_events if e.get("status") == "Missed"]
            live_history.append({
                'id': None,
                'attack': ev.get('attack'),
                'score': score,
                'time': ev.get('timestamp') or (ev.get('ts') or '')[:16],
                'events': chain_events,
                'weakest': weakest,
                'severity': ev.get('severity'),
                'source': 'live',
                'event_id': event.get("event_id"),
                '_ts': ev.get('ts')
            })
    live_db_history = _build_live_db_history(user_id=user_id)
    live_history = _merge_history(live_history, live_db_history)
    history = []
    if user_id:
        try:
            sims = Simulation.query.filter_by(user_id=user_id).order_by(Simulation.created_at.desc()).all()
            history = []
            for s in sims:
                src = "live" if _is_live_simulation(s) else "simulation"
                history.append({
                    'id': s.id,
                    'attack': s.attack_type,
                    'score': s.detection_score,
                    'time': s.created_at.strftime('%Y-%m-%d %H:%M'),
                    'events': s.events,
                    'weakest': s.weakest_stages or [],
                    'source': src,
                    'event_id': _extract_event_id(s.events),
                    '_ts': s.created_at.isoformat() if s.created_at else None
                })
        except Exception as e:
            print(f"Error fetching DB history for analytics: {e}")
            history = session.get('history', [])
    else:
        # Session history has less detail; normalize fields
        raw = session.get('history', [])
        history = []
        for h in raw:
            events = h.get('events', [])
            history.append({
                'id': None,
                'attack': h.get('attack'),
                'score': h.get('score'),
                'time': datetime.now().strftime('%Y-%m-%d ') + h.get('time', ''),
                'events': events,
                'weakest': h.get('weakest', []),
                'source': h.get('source') or 'simulation',
                'event_id': _extract_event_id(events),
                '_ts': None
            })
    if data_source in ("live", "simulation", "both"):
        return _merge_history(live_history, history)
    return _merge_history(live_history, history)

def _parse_history_time(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M")
    except Exception:
        return None

def _rolling_avg(history, days=7):
    cutoff = datetime.utcnow() - timedelta(days=days)
    scores = []
    for h in history:
        dt = _parse_history_time(h.get("time", ""))
        if dt and dt >= cutoff:
            scores.append(int(h.get("score", 0)))
    return round(sum(scores) / len(scores), 1) if scores else 0.0

def _prev_rolling_avg(history, days=7):
    end = datetime.utcnow() - timedelta(days=days)
    start = end - timedelta(days=days)
    scores = []
    for h in history:
        dt = _parse_history_time(h.get("time", ""))
        if dt and start <= dt < end:
            scores.append(int(h.get("score", 0)))
    return round(sum(scores) / len(scores), 1) if scores else 0.0

def _case_timeline(history, days=30):
    """Return date labels and counts for the last `days` days based on simulation timestamps."""
    counts = {}
    today = datetime.utcnow().date()
    for i in range(days-1, -1, -1):
        d = today - timedelta(days=i)
        counts[d.strftime('%Y-%m-%d')] = 0

    for h in history:
        try:
            date_str = h.get('time', '')[:10]
            if date_str in counts:
                counts[date_str] += 1
        except Exception:
            continue

    return {'labels': list(counts.keys()), 'values': list(counts.values())}


def _case_breakdown(history):
    """Categorize cases into severity buckets and return counts + percentages.
    Mapping is based on detection score (lower detection -> higher severity)."""
    buckets = {'4-Catastrophic': 0, '3-Critical': 0, '2-Marginal': 0, '1-Insignificant': 0, '0-None': 0}
    for h in history:
        score = int(h.get('score', 0))
        if score <= 20:
            buckets['4-Catastrophic'] += 1
        elif score <= 40:
            buckets['3-Critical'] += 1
        elif score <= 60:
            buckets['2-Marginal'] += 1
        elif score <= 80:
            buckets['1-Insignificant'] += 1
        else:
            buckets['0-None'] += 1

    total = sum(buckets.values()) or 1
    return {'counts': buckets, 'percent': {k: round(v / total * 100, 1) for k, v in buckets.items()}, 'total': total}


def _workflow_analysis(history):
    """Estimate workflow stage distribution from scores.
    Heuristic mapping: low score = early stage, high score = closed."""
    stages = {'Queued': 0, 'Initial': 0, 'Follow-up': 0, 'Final': 0, 'Closed': 0}
    for h in history:
        score = int(h.get('score', 0))
        if score < 20:
            stages['Queued'] += 1
        elif score < 40:
            stages['Initial'] += 1
        elif score < 60:
            stages['Follow-up'] += 1
        elif score < 80:
            stages['Final'] += 1
        else:
            stages['Closed'] += 1

    total = sum(stages.values()) or 1
    return {'counts': stages, 'percent': {k: round(v / total * 100, 1) for k, v in stages.items()}, 'total': total}


def _threat_analysis_funnel(history):
    """Compute funnel numbers: events analysed, correlation events (detected), and created cases (misses lead to cases)."""
    total_events = 0
    detected_events = 0
    created_cases = 0

    for h in history:
        evs = h.get('events') or []
        total_events += len(evs)
        for e in evs:
            if e.get('status') == 'Detected':
                detected_events += 1
        if h.get('weakest'):
            created_cases += 1

    # Avoid zero division
    conversion = round((detected_events / total_events * 100), 2) if total_events else 0
    case_creation_rate = round((created_cases / (len(history) or 1) * 100), 2)

    return {
        'analyzed': total_events,
        'found': detected_events,
        'created': created_cases,
        'found_pct': conversion,
        'created_pct': case_creation_rate
    }


def calculate_analytics(user_id=None, history_override=None, timeline_days=30):
    """Generate analytics data from simulation history.
    If `history_override` is provided, it will be used in place of DB/session history.
    If a `user_id` is provided and no override is given, use the user's DB simulations (most recent first).
    Otherwise, use session history. If AI is enabled, attempt AI computation and
    fall back to deterministic aggregation on failure."""
    history = history_override if history_override is not None else _build_history(user_id)

    if not history:
        return None

    # Try AI-based computation when available
    if AI_ENABLED:
        try:
            ai_result = ai_advisor.compute_metrics(history)
            if ai_result:
                ai_result['computed_by_ai'] = True
                # Merge additional deterministic analytics
                ai_result['case_timeline'] = _case_timeline(history, days=timeline_days)
                ai_result['case_breakdown'] = _case_breakdown(history)
                ai_result['workflow'] = _workflow_analysis(history)
                ai_result['funnel'] = _threat_analysis_funnel(history)
                ai_result['mitre_heatmap'] = _mitre_heatmap(history)
                ai_result['correlation'] = _correlation_matrix(history)
                ai_result['mitre_coverage'] = _mitre_coverage(history)
                ai_result['kill_chain_gaps'] = _kill_chain_gaps(history)
                ai_result['source_compare'] = _source_compare(history)
                ai_result['resource_monitor'] = _resource_monitoring(history, user_id=user_id)
                severity_counts = {"Catastrophic": 0, "Critical": 0, "Marginal": 0, "Low": 0, "None": 0}
                for h in history:
                    if h.get("severity"):
                        severity_counts[_severity_bucket_from_label(h.get("severity"))] += 1
                    else:
                        severity_counts[_severity_from_score(h.get("score", 0))] += 1
                ai_result['severity'] = severity_counts
                return ai_result
        except Exception as e:
            print(f"AI analytics computation failed: {e}")
            # fall back to deterministic computation

    # Deterministic fallback
    scores = [h['score'] for h in history]
    avg_score = sum(scores) / len(scores) if scores else 0

    attack_breakdown = {}
    for h in history:
        attack = h['attack']
        attack_breakdown.setdefault(attack, []).append(h['score'])

    recent_scores = [h['score'] for h in history][:10]

    analytics = {
        'avg_score': int(avg_score),
        'max_score': max(scores) if scores else 0,
        'min_score': min(scores) if scores else 0,
        'total_simulations': len(history),
        'attack_breakdown': {k: int(sum(v) / len(v)) for k, v in attack_breakdown.items()},
        'scores': recent_scores,
        'computed_by_ai': False
    }

    # Add new panels
    analytics['case_timeline'] = _case_timeline(history, days=timeline_days)
    case_break = _case_breakdown(history)
    analytics['case_breakdown'] = case_break
    # Flatten keys/values for safe JSON serialization in templates
    analytics['case_breakdown']['labels'] = list(case_break['counts'].keys())
    analytics['case_breakdown']['values'] = list(case_break['counts'].values())

    wf = _workflow_analysis(history)
    analytics['workflow'] = wf
    analytics['workflow']['labels'] = list(wf['counts'].keys())
    analytics['workflow']['values'] = list(wf['counts'].values())

    funnel = _threat_analysis_funnel(history)
    analytics['funnel'] = funnel

    analytics['mitre_heatmap'] = _mitre_heatmap(history)
    analytics['correlation'] = _correlation_matrix(history)
    analytics['mitre_coverage'] = _mitre_coverage(history)
    analytics['kill_chain_gaps'] = _kill_chain_gaps(history)
    analytics['source_compare'] = _source_compare(history)
    analytics['resource_monitor'] = _resource_monitoring(history, user_id=user_id)
    analytics['kpi'] = {
        "avg_7d": _rolling_avg(history, 7),
        "avg_30d": _rolling_avg(history, 30),
        "prev_7d": _prev_rolling_avg(history, 7)
    }

    severity_counts = {"Catastrophic": 0, "Critical": 0, "Marginal": 0, "Low": 0, "None": 0}
    for h in history:
        if h.get("severity"):
            severity_counts[_severity_bucket_from_label(h.get("severity"))] += 1
        else:
            severity_counts[_severity_from_score(h.get("score", 0))] += 1
    analytics['severity'] = severity_counts

    # Attack breakdown labels/values for charts
    analytics['attack_labels'] = list(analytics['attack_breakdown'].keys())
    analytics['attack_values'] = list(analytics['attack_breakdown'].values())

    return analytics

def _run_due_schedules(user_id):
    if not user_id:
        return
    now = datetime.utcnow()
    schedules = SimulationSchedule.query.filter_by(user_id=user_id, enabled=True).all()
    for sched in schedules:
        last = sched.last_run_at or (now - timedelta(minutes=sched.interval_minutes + 1))
        due = last + timedelta(minutes=sched.interval_minutes)
        if due <= now:
            preset = SimulationPreset.query.get(sched.preset_id)
            if preset:
                try:
                    _run_simulation_for_user(preset.attack_type, user_id, source="schedule")
                    sched.last_run_at = now
                    db.session.add(sched)
                    db.session.commit()
                except Exception as e:
                    print(f"Scheduled run failed: {e}")
                    db.session.rollback()
            break

def _run_due_schedules_background():
    now = datetime.utcnow()
    schedules = SimulationSchedule.query.filter_by(enabled=True).all()
    for sched in schedules:
        last = sched.last_run_at or (now - timedelta(minutes=sched.interval_minutes + 1))
        due = last + timedelta(minutes=sched.interval_minutes)
        if due <= now:
            preset = SimulationPreset.query.get(sched.preset_id)
            if preset:
                try:
                    _run_simulation_for_user_bg(preset.attack_type, sched.user_id)
                    sched.last_run_at = now
                    db.session.add(sched)
                    db.session.commit()
                except Exception as e:
                    print(f"Background schedule failed: {e}")
                    db.session.rollback()

def calculate_upgrade_roi():
    """Calculate ROI for each purchased upgrade"""
    upgrades_purchased = session.get('upgrades_purchased', {})
    history = session.get('history', [])
    
    roi_data = {}
    for upgrade_name, count in upgrades_purchased.items():
        if upgrade_name in UPGRADES and count > 0:
            cost = UPGRADES[upgrade_name]['cost'] * count
            roi_data[upgrade_name] = {
                'cost': cost,
                'units': count,
                'roi_multiplier': UPGRADES[upgrade_name]['roi'],
                'total_roi': cost * UPGRADES[upgrade_name]['roi']
            }
    
    return roi_data

def update_analytics_report(user_id, skip_ai=False):
    """Update or create user's analytics report"""
    try:
        report = AnalyticsReport.query.filter_by(user_id=user_id).first()
        if not report:
            report = AnalyticsReport(user_id=user_id)
        
        # Get all simulations for user
        simulations = Simulation.query.filter_by(user_id=user_id).all()
        
        if simulations:
            scores = [s.detection_score for s in simulations]
            report.total_simulations = len(simulations)
            report.average_score = sum(scores) / len(scores)
            report.max_score = max(scores)
            report.min_score = min(scores)
            
            # Attack breakdown
            attack_breakdown = {}
            for sim in simulations:
                if sim.attack_type not in attack_breakdown:
                    attack_breakdown[sim.attack_type] = []
                attack_breakdown[sim.attack_type].append(sim.detection_score)
            
            report.attack_breakdown = {
                attack: sum(scores) // len(scores) 
                for attack, scores in attack_breakdown.items()
            }
            
            # Find strongest/weakest defense
            if report.attack_breakdown:
                report.strongest_defense = max(report.attack_breakdown, key=report.attack_breakdown.get)
                report.weakest_defense = min(report.attack_breakdown, key=report.attack_breakdown.get)
            
            # Calculate total invested
            upgrades = UpgradePurchase.query.filter_by(user_id=user_id).all()
            report.total_invested = sum(u.cost for u in upgrades)
            
            # Generate AI insights if enabled
            if AI_ENABLED and report.total_simulations >= 3 and not skip_ai:
                try:
                    insights = ai_advisor.analyze_defense_strategy(
                        report.total_simulations,
                        report.average_score,
                        report.attack_breakdown,
                        report.total_invested
                    )
                    report.ai_insights = insights
                except Exception as e:
                    print(f"Error generating AI insights: {e}")
        
        db.session.add(report)
        db.session.commit()
    except Exception as e:
        print(f"Error updating analytics: {e}")
        db.session.rollback()

def map_log_to_event(log):
    """Convert incoming endpoint log into dashboard event format"""
    return {
        "stage": log.get("kill_chain_stage"),
        "status": "Detected" if log.get("detected") else "Missed",
        "tool": log.get("tool"),
        "reason": log.get("description") if log.get("detected") else "Detection failed",
        "miss_reason": log.get("miss_reason") if not log.get("detected") else "—",
        "time": log.get("timestamp", datetime.utcnow().strftime("%H:%M:%S")),
        "severity": log.get("severity")
    }

def _infer_stage(log):
    stage = (log.get("kill_chain_stage") or "").strip()
    if stage:
        return stage
    tool = (log.get("tool") or "").lower()
    desc = (log.get("description") or "").lower()

    # Tool-based mapping
    for s, t, _, _ in kill_chain_data:
        if t and t.lower() in tool:
            return s

    # Keyword-based mapping
    if any(k in desc for k in ["phish", "email", "attachment"]):
        return "Delivery"
    if any(k in desc for k in ["exploit", "rce", "vulnerability"]):
        return "Exploitation"
    if any(k in desc for k in ["install", "dropper", "payload", "malware"]):
        return "Installation"
    if any(k in desc for k in ["c2", "command", "control", "beacon"]):
        return "Command & Control"
    if any(k in desc for k in ["exfil", "steal", "dump", "objectives"]):
        return "Actions on Objectives"
    if any(k in desc for k in ["scan", "recon", "probe", "enumerat"]):
        return "Reconnaissance"
    return "Reconnaissance"

def _expand_chain_event(event):
    """Expand a single event into full kill-chain representation."""
    stage = event.get("stage")
    expanded = []
    for s, tool, _, _ in kill_chain_data:
        if s == stage:
            expanded.append(event)
        else:
            expanded.append({
                "stage": s,
                "status": "Not Observed",
                "tool": tool or "-",
                "reason": "-",
                "miss_reason": "-",
                "time": event.get("time")
            })
    return expanded

def _aggregate_live_chain(attack_type):
    """Aggregate recent live events into a kill-chain summary for one attack type."""
    stage_map = {}
    for ev in list(LIVE_EVENTS):
        if ev.get("attack") != attack_type:
            continue
        e = ev.get("event") or {}
        stage = e.get("stage")
        if stage and stage not in stage_map:
            stage_map[stage] = e
    aggregated = []
    for s, tool, _, _ in kill_chain_data:
        if s in stage_map:
            aggregated.append(stage_map[s])
        else:
            aggregated.append({
                "stage": s,
                "status": "Not Observed",
                "tool": tool or "-",
                "reason": "-",
                "miss_reason": "-",
                "time": None
            })
    return aggregated

def _recommendations_for_event(event):
    """Build simulation-style remediation guidance for a single missed event."""
    stage = (event or {}).get("stage")
    status = (event or {}).get("status")
    if status != "Missed" or stage not in recommendations_map:
        return []
    rec = recommendations_map[stage]
    return [{
        "stage": stage,
        "improve": rec["improve"],
        "response": rec["response"]
    }]

def _build_live_analysis(event, chain_events, aggregate_chain, recommendations, iocs):
    """Build rich live-log analysis similar to simulation output."""
    snapshot = aggregate_chain if aggregate_chain else chain_events
    snapshot = snapshot or ([event] if event else [])
    total_stages = len(kill_chain_data) or 1

    observed = []
    detected = []
    missed = []
    for item in snapshot:
        stage = item.get("stage")
        status = item.get("status")
        if not stage:
            continue
        if status in ("Detected", "Missed"):
            observed.append(stage)
        if status == "Detected":
            detected.append(stage)
        elif status == "Missed":
            missed.append(stage)

    score = int((len(detected) / total_stages) * 100)
    coverage_pct = round((len(set(observed)) / total_stages) * 100, 2)

    if len(missed) >= 2:
        risk_level = "high"
    elif len(missed) == 1:
        risk_level = "medium"
    elif len(observed) == 0:
        risk_level = "unknown"
    else:
        risk_level = "low"

    return {
        "score": score,
        "coverage_pct": coverage_pct,
        "observed_stages": list(dict.fromkeys(observed)),
        "weakest_stages": list(dict.fromkeys(missed)),
        "risk_level": risk_level,
        "ioc_count": len(iocs or []),
        "recommendation_count": len(recommendations or []),
        "chain_snapshot": snapshot
    }

def _severity_from_score(score):
    s = int(score or 0)
    if s <= 20:
        return "Catastrophic"
    if s <= 40:
        return "Critical"
    if s <= 60:
        return "Marginal"
    if s <= 80:
        return "Low"
    return "None"

def _severity_bucket_from_label(label):
    s = (label or "").strip().lower()
    if s == "critical":
        return "Critical"
    if s == "high":
        return "Catastrophic"
    if s == "medium":
        return "Marginal"
    if s == "low":
        return "Low"
    return "None"

def _normalize_severity(value):
    s = (value or "").strip().lower()
    if s in ("critical", "catastrophic"):
        return "critical"
    if s in ("high", "severe"):
        return "high"
    if s in ("medium", "moderate"):
        return "medium"
    if s in ("low", "info", "none"):
        return "low"
    return "medium"

def _severity_rank(value):
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get((value or "").lower(), 2)

def _build_live_brief(events):
    if not events:
        return "No live events yet."
    attacks = {}
    missed = {}
    for e in events:
        attack = e.get("attack") or "Unknown"
        attacks[attack] = attacks.get(attack, 0) + 1
        if (e.get("event") or {}).get("status") == "Missed":
            stage = (e.get("event") or {}).get("stage") or "Unknown"
            missed[stage] = missed.get(stage, 0) + 1
    top_attacks = sorted(attacks.items(), key=lambda x: x[1], reverse=True)[:3]
    top_missed = sorted(missed.items(), key=lambda x: x[1], reverse=True)[:3]
    lines = ["Live brief:"]
    if top_attacks:
        lines.append("Top attacks: " + ", ".join([f"{a} ({c})" for a, c in top_attacks]))
    if top_missed:
        lines.append("Most missed stages: " + ", ".join([f"{s} ({c})" for s, c in top_missed]))
    return "\n".join(lines)

def _fallback_recommendation_explain(event, recommendations):
    if not recommendations:
        return "No recommendations were generated for this event."
    stage = (event or {}).get("stage") or "this stage"
    return f"Recommendations focus on improving detection at {stage} based on recent misses."

def _fallback_next_steps(attack_type):
    playbook = incident_playbooks.get(attack_type, {}).get("blue_team") if attack_type else []
    if playbook:
        return playbook[:4]
    return [
        "Review relevant alerts and logs",
        "Isolate impacted systems if needed",
        "Collect evidence and preserve artifacts",
        "Escalate to incident response lead"
    ]

def _fallback_case_summary(case, notes, sim):
    lines = [
        f"Case '{case.title}' is currently {case.status} with severity {case.severity}.",
        f"Description: {case.description or 'No description provided.'}"
    ]
    if sim:
        lines.append(f"Linked simulation: {sim.attack_type} with detection score {sim.detection_score}%.")
    if notes:
        lines.append(f"Latest note: {notes[0].note}")
    lines.append("Next action: review evidence and update status.")
    return " ".join(lines)

def _fallback_root_cause(events):
    missed = [e.get("stage") for e in (events or []) if e.get("status") == "Missed"]
    if not missed:
        return "No missed stages detected; focus on validating detections and tuning thresholds."
    uniq = ", ".join(sorted(set([m for m in missed if m])))
    return f"Likely control gaps at stages: {uniq}. Review tooling, coverage, and detection logic for these stages."

def _fallback_triage(case, sim):
    sev_map = {"low": 20, "medium": 50, "high": 75, "critical": 90}
    base = sev_map.get((case.severity or "medium").lower(), 50)
    if case.status in ("Investigating", "Escalated"):
        base = min(100, base + 10)
    if sim:
        base = min(100, base + max(0, 60 - (sim.detection_score or 0)) // 2)
    label = "Low" if base < 40 else "Medium" if base < 70 else "High" if base < 90 else "Critical"
    return {"score": int(base), "label": label, "rationale": "Heuristic triage score based on severity and status."}

def _case_description_from_event(payload):
    ev = payload.get("event") or {}
    iocs = payload.get("iocs") or []
    lines = [
        f"Attack: {payload.get('attack')}",
        f"Stage: {ev.get('stage')}",
        f"Status: {ev.get('status')}",
        f"Severity: {payload.get('severity')}",
        f"Tool: {ev.get('tool')}",
        f"Reason: {ev.get('reason')}",
    ]
    if ev.get("miss_reason") and ev.get("miss_reason") != "â€”":
        lines.append(f"Miss Reason: {ev.get('miss_reason')}")
    if iocs:
        lines.append("IOCs:")
        for ioc in iocs[:10]:
            lines.append(f"- {ioc.get('type')}: {ioc.get('value')}")
    return "\n".join([l for l in lines if l])

def _create_case_from_event(user_id, payload, title_prefix="Live Alert"):
    ev = payload.get("event") or {}
    title = f"{title_prefix}: {payload.get('attack')} - {ev.get('stage')}"
    case = Case(
        user_id=user_id,
        title=title,
        description=_case_description_from_event(payload),
        status="Investigating",
        severity=(payload.get("severity") or "Medium").title()
    )
    db.session.add(case)
    db.session.commit()
    for ioc in payload.get("iocs") or []:
        indicator = Indicator.query.filter_by(
            indicator_type=ioc.get("type"), value=ioc.get("value")
        ).first()
        if indicator:
            db.session.add(IndicatorRelation(
                indicator_id=indicator.id,
                relation_type="case",
                relation_id=str(case.id),
                meta={"source": "live_event"}
            ))
    db.session.commit()
    _record_case_event(case.id, user_id, "case_created", {"source": "live_event"})
    return case

def _match_alert_rule(rule, payload):
    ev = payload.get("event") or {}
    if rule.attack_type and rule.attack_type != payload.get("attack"):
        return False
    if rule.stage and rule.stage != ev.get("stage"):
        return False
    if rule.status and rule.status != ev.get("status"):
        return False
    sev = (payload.get("severity") or "medium").lower()
    if _severity_rank(sev) < _severity_rank(rule.severity_threshold):
        return False
    return True

def _es_enabled():
    return bool(ES_URL)

def _es_headers():
    headers = {"Content-Type": "application/json"}
    if ES_API_KEY:
        headers["Authorization"] = f"ApiKey {ES_API_KEY}"
    elif ES_USER and ES_PASS:
        token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    return headers

def _es_request(method, path, body=None):
    if not _es_enabled():
        return None
    url = ES_URL.rstrip("/") + "/" + path.lstrip("/")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in _es_headers().items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except Exception as e:
        print(f"Elasticsearch request failed: {e}")
        return None

def _es_index(index, doc):
    return _es_request("POST", f"{index}/_doc", doc)

def _es_search(index, query, size=25):
    body = {
        "query": {
            "multi_match": {
                "query": query,
                "fields": [
                    "attack_type^2",
                    "stage",
                    "status",
                    "tool",
                    "reason",
                    "miss_reason",
                    "description",
                    "kill_chain_stage",
                    "source"
                ]
            }
        },
        "size": size,
        "sort": [{"@timestamp": "desc"}]
    }
    return _es_request("POST", f"{index}/_search", body)

def _index_simulation_events(attack_type, score, events, user_id=None):
    if not _es_enabled():
        return
    ts = datetime.utcnow().isoformat()
    for ev in events:
        doc = {
            "@timestamp": ts,
            "source": "simulation",
            "attack_type": attack_type,
            "score": score,
            "stage": ev.get("stage"),
            "status": ev.get("status"),
            "tool": ev.get("tool"),
            "reason": ev.get("reason"),
            "miss_reason": ev.get("miss_reason"),
            "user_id": user_id
        }
        _es_index(ES_SIM_INDEX, doc)

def _index_live_log(log, mapped_event):
    if not _es_enabled():
        return
    doc = {
        "@timestamp": datetime.utcnow().isoformat(),
        "source": "live_log",
        "attack_type": log.get("attack_type"),
        "kill_chain_stage": log.get("kill_chain_stage"),
        "tool": log.get("tool"),
        "detected": log.get("detected"),
        "description": log.get("description"),
        "miss_reason": log.get("miss_reason"),
        "stage": mapped_event.get("stage"),
        "status": mapped_event.get("status")
    }
    _es_index(ES_LOG_INDEX, doc)

def _normalize_hit(source):
    return {
        "type": source.get("source", "unknown"),
        "time": source.get("@timestamp"),
        "attack": source.get("attack_type"),
        "stage": source.get("stage") or source.get("kill_chain_stage"),
        "status": source.get("status") or ("Detected" if source.get("detected") else "Missed"),
        "tool": source.get("tool"),
        "details": source.get("reason") or source.get("description") or source.get("miss_reason")
    }

def search_all(query, user_id=None, limit=25):
    results = []
    if _es_enabled():
        for idx in (ES_SIM_INDEX, ES_LOG_INDEX):
            resp = _es_search(idx, query, size=limit)
            hits = (((resp or {}).get("hits") or {}).get("hits")) or []
            for h in hits:
                src = h.get("_source") or {}
                results.append(_normalize_hit(src))
    else:
        # Fallback to local/session data
        q = (query or "").lower()
        history = _build_history(user_id)
        for h in history:
            for ev in h.get("events", []):
                hay = json.dumps({"attack": h.get("attack"), "score": h.get("score"), "event": ev}).lower()
                if q in hay:
                    results.append({
                        "type": "simulation",
                        "time": h.get("time"),
                        "attack": h.get("attack"),
                        "stage": ev.get("stage"),
                        "status": ev.get("status"),
                        "tool": ev.get("tool"),
                        "details": ev.get("reason") or ev.get("miss_reason")
                    })
        for log in received_logs:
            hay = json.dumps(log).lower()
            if q in hay:
                results.append({
                    "type": "live_log",
                    "time": log.get("timestamp"),
                    "attack": log.get("attack_type"),
                    "stage": log.get("kill_chain_stage"),
                    "status": "Detected" if log.get("detected") else "Missed",
                    "tool": log.get("tool"),
                    "details": log.get("description") or log.get("miss_reason")
                })

    return results[:limit]

def _require_roles(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return redirect(url_for('login'))
            user = User.query.get(user_id)
            if not user or user.role not in roles:
                flash("Access denied for your role.", "error")
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def _mitre_heatmap(history):
    counts = {}
    for h in history:
        attack = h.get("attack")
        for code, name in MITRE_ATTACK_MAPPING.get(attack, []):
            key = f"{code} {name}"
            counts[key] = counts.get(key, 0) + 1
    items = [{"technique": k, "count": v} for k, v in counts.items()]
    items.sort(key=lambda x: x["count"], reverse=True)
    return items

def _mitre_coverage(history):
    all_techniques = set()
    for _, items in MITRE_ATTACK_MAPPING.items():
        for code, name in items:
            all_techniques.add(f"{code} {name}")
    seen = set()
    for h in history:
        attack = h.get("attack")
        for code, name in MITRE_ATTACK_MAPPING.get(attack, []):
            seen.add(f"{code} {name}")
    total = len(all_techniques) or 1
    coverage = round((len(seen) / total) * 100, 1)
    gaps = sorted(list(all_techniques - seen))
    return {"coverage": coverage, "total": total, "seen": len(seen), "gaps": gaps}

def _ioc_technique_cooccurrence(user_id=None, ioc_type=None, attack_type=None, max_indicators=240, max_links=45):
    query = Indicator.query.order_by(Indicator.last_seen.desc())
    if ioc_type:
        query = query.filter(Indicator.indicator_type == ioc_type)
    if attack_type:
        query = query.filter(Indicator.last_seen_attack == attack_type)
    indicators = query.limit(max_indicators).all()

    edge_weights = Counter()
    node_weights = Counter()
    ioc_count = 0

    for ind in indicators:
        attack = (ind.last_seen_attack or "").strip()
        if attack not in MITRE_ATTACK_MAPPING:
            continue

        ioc_count += 1
        raw_ioc = f"{ind.indicator_type}:{ind.value}"
        ioc_label = raw_ioc if len(raw_ioc) <= 44 else f"{raw_ioc[:41]}..."
        weight = max(1, min(int(ind.count or 1), 10))

        for code, name in MITRE_ATTACK_MAPPING.get(attack, []):
            tech_label = f"{code} {name}"
            edge_weights[(ioc_label, tech_label)] += weight
            node_weights[ioc_label] += weight
            node_weights[tech_label] += weight

    top_edges = sorted(edge_weights.items(), key=lambda kv: kv[1], reverse=True)[:max_links]

    nodes_map = {}
    nodes = []
    links = []

    def _node_id(prefix, label):
        return f"{prefix}:{hashlib.sha1(label.encode('utf-8')).hexdigest()[:10]}"

    for (ioc_label, tech_label), weight in top_edges:
        if ioc_label not in nodes_map:
            nid = _node_id("ioc", ioc_label)
            nodes_map[ioc_label] = nid
            nodes.append({
                "id": nid,
                "label": ioc_label,
                "type": "ioc",
                "value": int(node_weights[ioc_label])
            })
        if tech_label not in nodes_map:
            nid = _node_id("tech", tech_label)
            nodes_map[tech_label] = nid
            nodes.append({
                "id": nid,
                "label": tech_label,
                "type": "technique",
                "value": int(node_weights[tech_label])
            })
        links.append({
            "source": nodes_map[ioc_label],
            "target": nodes_map[tech_label],
            "weight": int(weight)
        })

    return {
        "nodes": nodes,
        "links": links,
        "summary": {
            "indicators_considered": int(ioc_count),
            "cooccurrences": int(len(top_edges)),
            "filters": {
                "ioc_type": ioc_type or "all",
                "attack_type": attack_type or "all",
                "top_links": int(max_links)
            }
        }
    }

def _correlation_matrix(history):
    stages = [s[0] for s in kill_chain_data]
    index = {s: i for i, s in enumerate(stages)}
    size = len(stages)
    matrix = [[0 for _ in range(size)] for _ in range(size)]

    for h in history:
        evs = h.get("events") or []
        missed = [e.get("stage") for e in evs if e.get("status") == "Missed"]
        for i in range(len(missed)):
            for j in range(i, len(missed)):
                a, b = missed[i], missed[j]
                if a in index and b in index:
                    matrix[index[a]][index[b]] += 1
                    if a != b:
                        matrix[index[b]][index[a]] += 1

    return {"stages": stages, "matrix": matrix}

def _kill_chain_gaps(history, top_n=3):
    gaps = {s[0]: 0 for s in kill_chain_data}
    for h in history:
        evs = h.get("events") or []
        for e in evs:
            status = e.get("status")
            stage = e.get("stage")
            if stage in gaps and status in ("Missed", "Not Observed"):
                gaps[stage] += 1
    ranked = sorted(gaps.items(), key=lambda x: x[1], reverse=True)
    return [{"stage": s, "count": c} for s, c in ranked[:top_n]]

def _source_compare(history):
    live_scores = []
    sim_scores = []
    for h in history:
        if h.get("source") == "live":
            live_scores.append(h.get("score", 0))
        else:
            sim_scores.append(h.get("score", 0))
    def _avg(lst):
        return int(sum(lst) / len(lst)) if lst else 0
    return {
        "live_avg": _avg(live_scores),
        "sim_avg": _avg(sim_scores),
        "live_count": len(live_scores),
        "sim_count": len(sim_scores)
    }

def _resource_monitoring(history, user_id=None):
    minute_buckets = {}
    total_events = 0
    detected_events = 0
    missed_events = 0
    total_sims = len(history or [])

    for h in history or []:
        ts = _parse_event_time(h.get("_ts") or h.get("time"))
        if not ts:
            continue
        minute_key = ts.replace(second=0, microsecond=0)
        evs = h.get("events") or []
        event_count = len(evs)
        total_events += event_count
        minute_buckets[minute_key] = minute_buckets.get(minute_key, 0) + event_count

        for ev in evs:
            status = (ev.get("status") or "").strip()
            if status == "Detected":
                detected_events += 1
            elif status in ("Missed", "Not Observed"):
                missed_events += 1

    ordered = sorted(minute_buckets.items(), key=lambda kv: kv[0])[-20:]
    eps_labels = [k.strftime("%m-%d %H:%M") for k, _ in ordered]
    eps_values = [round(v / 60.0, 3) for _, v in ordered]

    avg_eps = round(sum(eps_values) / len(eps_values), 3) if eps_values else 0.0
    peak_eps = max(eps_values) if eps_values else 0.0
    detection_rate = round((detected_events / total_events) * 100, 1) if total_events else 0.0
    noise_rate = round((missed_events / total_events) * 100, 1) if total_events else 0.0
    signal_quality = max(0.0, round(100.0 - noise_rate, 1))
    throughput_health = min(100.0, round(avg_eps * 240, 1))

    day_counts = {}
    today = datetime.utcnow().date()
    for i in range(9, -1, -1):
        d = today - timedelta(days=i)
        day_counts[d.strftime("%Y-%m-%d")] = 0
    for h in history or []:
        ts = _parse_event_time(h.get("_ts") or h.get("time"))
        if not ts:
            continue
        key = ts.strftime("%Y-%m-%d")
        if key in day_counts:
            day_counts[key] += len(h.get("events") or [])
    daily_labels = list(day_counts.keys())
    daily_eps_values = [round(v / 86400.0, 4) for v in day_counts.values()]

    device_counter = Counter()
    log_type_counter = Counter()
    host_counter = Counter()
    device_volume = Counter()
    log_type_volume = Counter()
    host_volume = Counter()
    raw_timeline = Counter()

    try:
        q = LiveLog.query
        if user_id:
            q = q.filter(or_(LiveLog.user_id == user_id, LiveLog.user_id.is_(None)))
        rows = q.order_by(LiveLog.created_at.desc()).limit(500).all()
    except Exception:
        rows = []

    for row in rows:
        raw = row.raw_log or {}
        ts = row.created_at
        if ts:
            minute_key = ts.replace(second=0, microsecond=0)
            raw_timeline[minute_key] += 1
        device = str(raw.get("device_type") or raw.get("platform") or raw.get("source") or "unknown")
        log_type = str(raw.get("log_type") or raw.get("tool") or raw.get("kill_chain_stage") or "event")
        host = str(raw.get("host") or raw.get("hostname") or raw.get("source_ip") or raw.get("dest_ip") or "unknown")
        volume_bytes = len(json.dumps(raw, default=str).encode("utf-8"))
        device_counter[device] += 1
        log_type_counter[log_type] += 1
        host_counter[host] += 1
        device_volume[device] += volume_bytes
        log_type_volume[log_type] += volume_bytes
        host_volume[host] += volume_bytes

    def _fmt_bytes(n):
        if n >= 1024 * 1024:
            return f"{round(n / (1024 * 1024), 2)} MB"
        if n >= 1024:
            return f"{round(n / 1024, 1)} KB"
        return f"{int(n)} B"

    def _rows(counter, volume_counter, top_n=6):
        out = []
        for name, count in counter.most_common(top_n):
            out.append({"name": name, "count": int(count), "volume": _fmt_bytes(volume_counter.get(name, 0))})
        return out

    raw_points = sorted(raw_timeline.items(), key=lambda kv: kv[0])[-30:]
    raw_labels = [k.strftime("%m-%d %H:%M") for k, _ in raw_points]
    raw_values = [int(v) for _, v in raw_points]

    return {
        "eps_labels": eps_labels,
        "eps_values": eps_values,
        "daily_labels": daily_labels,
        "daily_eps_values": daily_eps_values,
        "raw_labels": raw_labels,
        "raw_values": raw_values,
        "kpi_labels": ["Detection Rate", "Signal Quality", "Throughput Health"],
        "kpi_values": [detection_rate, signal_quality, throughput_health],
        "device_rows": _rows(device_counter, device_volume),
        "log_type_rows": _rows(log_type_counter, log_type_volume),
        "host_rows": _rows(host_counter, host_volume),
        "totals": {
            "simulations": int(total_sims),
            "events": int(total_events),
            "avg_eps": float(avg_eps),
            "peak_eps": float(peak_eps)
        }
    }

def _kpi_dashboard_rows(history):
    grouped = {}
    for h in history or []:
        attack = (h.get("attack") or "Unknown").strip() or "Unknown"
        row = grouped.setdefault(attack, {
            "company": attack,
            "branch": "SOC Main",
            "sim_count": 0,
            "score_sum": 0.0,
            "alarm": 0,
            "correlation": 0,
            "threat": 0,
            "fp_count": 0,
            "use_alarm": 0,
            "use_correlation": 0,
            "use_log": 0,
            "inc_alarm": 0,
            "inc_correlation": 0
        })
        events = h.get("events") or []
        total_events = len(events)
        detected = 0
        missed = 0
        for ev in events:
            status = (ev.get("status") or "").strip()
            if status == "Detected":
                detected += 1
            elif status in ("Missed", "Not Observed"):
                missed += 1

        row["sim_count"] += 1
        row["score_sum"] += float(h.get("score") or 0)
        row["alarm"] += total_events
        row["correlation"] += detected
        row["threat"] += missed
        row["fp_count"] += max(0, total_events - detected - missed)
        row["use_alarm"] += 1
        row["use_correlation"] += 1 if detected > 0 else 0
        row["use_log"] += 1 if (h.get("source") == "live") else 0
        row["inc_alarm"] += 1 if missed > 0 else 0
        row["inc_correlation"] += 1 if float(h.get("score") or 0) < 40 else 0

    rows = []
    for _, r in grouped.items():
        avg_score = (r["score_sum"] / r["sim_count"]) if r["sim_count"] else 0.0
        mttd_min = round(max(0.0, (100.0 - avg_score) / 10.0), 1)
        mttr_hr = round(max(0.0, (100.0 - avg_score) / 25.0), 1)
        rows.append({
            "company": r["company"],
            "branch": r["branch"],
            "mttd_min": mttd_min,
            "mttr_hr": mttr_hr,
            "alarm": int(r["alarm"]),
            "correlation": int(r["correlation"]),
            "threat": int(r["threat"]),
            "fp_count": int(r["fp_count"]),
            "use_alarm": int(r["use_alarm"]),
            "use_correlation": int(r["use_correlation"]),
            "use_log": int(r["use_log"]),
            "inc_alarm": int(r["inc_alarm"]),
            "inc_correlation": int(r["inc_correlation"])
        })
    rows.sort(key=lambda x: x["alarm"], reverse=True)
    return rows

def _compute_rule_effectiveness(user_id, lookback_days=30, trend_days=14):
    rules = AlertRule.query.filter(
        or_(AlertRule.user_id == user_id, AlertRule.user_id.is_(None))
    ).order_by(AlertRule.created_at.desc()).all()

    history = _build_history(user_id)
    cutoff = datetime.utcnow() - timedelta(days=lookback_days)
    events = []

    for h in history:
        ts = _parse_event_time(h.get("_ts") or h.get("time")) or datetime.utcnow()
        if ts < cutoff:
            continue
        attack = h.get("attack")
        base_severity = _normalize_severity(h.get("severity") or ATTACK_SEVERITY.get(attack))
        for ev in (h.get("events") or []):
            status = (ev.get("status") or "").strip()
            if not status:
                continue
            events.append({
                "day": ts.strftime("%Y-%m-%d"),
                "attack": attack,
                "stage": (ev.get("stage") or "").strip(),
                "status": status,
                "severity": _normalize_severity(ev.get("severity") or base_severity)
            })

    def in_scope(rule, rec):
        if rule.attack_type and rec["attack"] != rule.attack_type:
            return False
        if rule.stage and rec["stage"] != rule.stage:
            return False
        if _severity_rank(rec["severity"]) < _severity_rank(rule.severity_threshold):
            return False
        return True

    today = datetime.utcnow().date()
    trend_labels = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(trend_days - 1, -1, -1)]

    per_rule = []
    for rule in rules:
        target_status = (rule.status or "Missed").strip()
        scoped = [rec for rec in events if in_scope(rule, rec)]
        predicted = len(scoped)
        tp = sum(1 for rec in scoped if rec["status"] == target_status)
        fp = max(0, predicted - tp)

        positives = sum(
            1 for rec in events
            if rec["status"] == target_status and _severity_rank(rec["severity"]) >= _severity_rank(rule.severity_threshold)
        )
        precision = round((tp / predicted) * 100, 1) if predicted else 0.0
        recall = round((tp / positives) * 100, 1) if positives else 0.0

        precision_trend = []
        recall_trend = []
        for day in trend_labels:
            day_scoped = [rec for rec in scoped if rec["day"] == day]
            day_pred = len(day_scoped)
            day_tp = sum(1 for rec in day_scoped if rec["status"] == target_status)
            day_pos = sum(
                1 for rec in events
                if rec["day"] == day and rec["status"] == target_status and _severity_rank(rec["severity"]) >= _severity_rank(rule.severity_threshold)
            )
            day_precision = round((day_tp / day_pred) * 100, 1) if day_pred else 0.0
            day_recall = round((day_tp / day_pos) * 100, 1) if day_pos else 0.0
            precision_trend.append(day_precision)
            recall_trend.append(day_recall)

        per_rule.append({
            "id": rule.id,
            "name": rule.name,
            "enabled": bool(rule.enabled),
            "attack_type": rule.attack_type or "Any",
            "stage": rule.stage or "Any",
            "status": target_status,
            "severity_threshold": rule.severity_threshold,
            "predicted": predicted,
            "tp": tp,
            "fp": fp,
            "precision": precision,
            "recall": recall,
            "precision_trend": precision_trend,
            "recall_trend": recall_trend
        })

    top_noisy = sorted(
        [r for r in per_rule if r["predicted"] > 0],
        key=lambda r: (r["fp"], -r["precision"], r["predicted"]),
        reverse=True
    )[:5]

    return {
        "rules": per_rule,
        "top_noisy": top_noisy,
        "event_count": len(events),
        "trend_labels": trend_labels
    }

def _run_simulation_for_user(attack_type, user_id, source="manual", variant="standard"):
    events, score, weakest, recs = get_simulation(attack_type, variant=variant)

    # Save to DB
    if user_id:
        sim = Simulation(
            user_id=user_id,
            attack_type=attack_type,
            detection_score=score,
            events=events,
            weakest_stages=weakest,
            variant=variant
        )
        if AI_ENABLED:
            try:
                threat_narrative = ai_advisor.generate_threat_narrative(attack_type, score, events)
                sim.threat_narrative = threat_narrative
                ai_recs = ai_advisor.generate_intelligent_recommendations(
                    attack_type, score, weakest, session.get('upgrades', {})
                )
                sim.ai_recommendations = ai_recs
            except Exception as e:
                print(f"Error generating AI insights: {e}")
        db.session.add(sim)
        db.session.commit()

    # Update session history
    history = session.get("history", [])
    history.insert(0, {
        "attack": attack_type,
        "score": score,
        "time": datetime.now().strftime("%H:%M"),
        "events": events,
        "weakest": weakest,
        "source": source
    })
    session["history"] = history
    session.modified = True

    _index_simulation_events(attack_type, score, events, user_id=user_id)
    for ev in events:
        _record_threat_discovery("simulation", {
            "attack_type": attack_type,
            "stage": ev.get("stage"),
            "tool": ev.get("tool"),
            "status": ev.get("status"),
            "reason": ev.get("reason"),
            "miss_reason": ev.get("miss_reason")
        })
    return events, score, weakest, recs

def _run_simulation_for_user_bg(attack_type, user_id):
    events, score, weakest, recs = get_simulation_with_upgrades(attack_type, {})
    sim = Simulation(
        user_id=user_id,
        attack_type=attack_type,
        detection_score=score,
        events=events,
        weakest_stages=weakest
    )
    db.session.add(sim)
    db.session.commit()
    _index_simulation_events(attack_type, score, events, user_id=user_id)
    return events, score

def _record_audit(actor_id, action, meta=None):
    try:
        db.session.add(AuditLog(actor_id=actor_id, action=action, meta=meta or {}))
        db.session.commit()
    except Exception as e:
        print(f"Audit log failed: {e}")
        db.session.rollback()

def _record_case_event(case_id, actor_id, action, meta=None):
    try:
        db.session.add(CaseEvent(case_id=case_id, actor_id=actor_id, action=action, meta=meta or {}))
        db.session.commit()
    except Exception as e:
        print(f"Case event log failed: {e}")
        db.session.rollback()

def _ensure_case_checklist(case_id):
    existing = CaseChecklistItem.query.filter_by(case_id=case_id).count()
    if existing:
        return
    for fw, items in COMPLIANCE_CHECKLISTS.items():
        for item in items:
            db.session.add(CaseChecklistItem(case_id=case_id, framework=fw, item=item, status="open"))
    db.session.commit()

def _weekly_report_data(days=7):
    history = _build_history(session.get("user_id"))
    cutoff = datetime.utcnow() - timedelta(days=days)
    filtered = []
    for h in history:
        ts = _parse_event_time(h.get("_ts") or h.get("time"))
        if ts and ts >= cutoff:
            filtered.append(h)
    total = len(filtered)
    if not total:
        return {"days": days, "total": 0}
    attacks = {}
    misses = {}
    for h in filtered:
        attacks[h.get("attack")] = attacks.get(h.get("attack"), 0) + 1
        for e in h.get("events") or []:
            if e.get("status") in ("Missed", "Not Observed"):
                misses[e.get("stage")] = misses.get(e.get("stage"), 0) + 1
    top_attacks = sorted(attacks.items(), key=lambda x: x[1], reverse=True)[:5]
    top_misses = sorted(misses.items(), key=lambda x: x[1], reverse=True)[:5]
    analytics = calculate_analytics(session.get("user_id"))
    return {
        "days": days,
        "total": total,
        "top_attacks": top_attacks,
        "top_misses": top_misses,
        "avg_score": analytics.get("avg_score") if analytics else 0,
        "kill_chain_gaps": analytics.get("kill_chain_gaps") if analytics else []
    }

def _get_widget_prefs(user_id):
    keys = ["analytics", "summary", "history", "search_results"]
    prefs = {k: True for k in keys}
    if not user_id:
        return prefs
    rows = UserWidget.query.filter_by(user_id=user_id).all()
    if not rows:
        return prefs
    for r in rows:
        if r.widget_key in prefs:
            prefs[r.widget_key] = bool(r.enabled)
    return prefs

def _threat_fingerprint(payload):
    base = {
        "attack_type": payload.get("attack_type"),
        "stage": payload.get("stage") or payload.get("kill_chain_stage"),
        "tool": payload.get("tool"),
        "status": payload.get("status") or ("Detected" if payload.get("detected") else "Missed"),
        "reason": payload.get("reason") or payload.get("description") or payload.get("miss_reason"),
    }
    raw = json.dumps(base, sort_keys=True).lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def _record_threat_discovery(source, payload):
    fingerprint = _threat_fingerprint(payload)
    now = datetime.utcnow()
    sig = ThreatSignature.query.filter_by(fingerprint=fingerprint).first()
    settings = ThreatSettings.query.first()
    threshold = settings.anomaly_threshold if settings else 2
    auto_case = settings.auto_case if settings else True

    if not sig:
        sig = ThreatSignature(fingerprint=fingerprint, count=1, first_seen=now, last_seen=now, status="new")
        db.session.add(sig)
        db.session.commit()
        db.session.add(ThreatDiscovery(signature_id=sig.id, source=source, sample=payload))
        db.session.commit()
        if auto_case and session.get("user_id"):
            case = Case(
                user_id=session.get("user_id"),
                title="Auto-case: new threat pattern",
                description=f"Discovered new threat pattern from {source}.",
                status="Investigating",
                severity="Critical"
            )
            db.session.add(case)
            db.session.commit()
        return sig, True

    sig.count += 1
    sig.last_seen = now
    db.session.add(sig)
    db.session.commit()
    if sig.count <= threshold:
        db.session.add(ThreatDiscovery(signature_id=sig.id, source=source, sample=payload))
        db.session.commit()
    return sig, False

def _enrich_ip(ip_value):
    try:
        ip_obj = ipaddress.ip_address(ip_value)
        if ip_obj.is_private:
            ip_type = "private"
        elif ip_obj.is_loopback:
            ip_type = "loopback"
        elif ip_obj.is_multicast:
            ip_type = "multicast"
        else:
            ip_type = "public"
        return {"ip_type": ip_type}
    except Exception:
        return {"ip_type": "invalid"}

def _extract_iocs(log):
    iocs = []
    if log.get("source_ip"):
        iocs.append({"type": "ip", "value": log.get("source_ip")})
    if log.get("dest_ip"):
        iocs.append({"type": "ip", "value": log.get("dest_ip")})
    if log.get("domain"):
        iocs.append({"type": "domain", "value": log.get("domain")})
    if log.get("url"):
        iocs.append({"type": "url", "value": log.get("url")})
    if log.get("file_hash"):
        iocs.append({"type": "hash", "value": log.get("file_hash")})
    if log.get("hash"):
        iocs.append({"type": "hash", "value": log.get("hash")})
    if log.get("email"):
        iocs.append({"type": "email", "value": log.get("email")})
    if log.get("sender"):
        iocs.append({"type": "email", "value": log.get("sender")})
    return iocs

def _default_expiry(indicator_type):
    if indicator_type == "ip":
        return datetime.utcnow() + timedelta(days=30)
    if indicator_type == "url":
        return datetime.utcnow() + timedelta(days=14)
    return datetime.utcnow() + timedelta(days=90)

def _record_indicator(indicator_type, value, source="log", attack_type=None, stage=None, confidence=0.5):
    if not value:
        return None
    enrichment = _enrich_ip(value) if indicator_type == "ip" else {}
    now = datetime.utcnow()
    indicator = Indicator.query.filter_by(indicator_type=indicator_type, value=value).first()
    if not indicator:
        indicator = Indicator(
            indicator_type=indicator_type,
            value=value,
            enrichment=enrichment,
            confidence=confidence,
            status="new",
            source=source,
            last_seen_attack=attack_type,
            last_seen_stage=stage,
            count=1,
            first_seen=now,
            last_seen=now,
            expires_at=_default_expiry(indicator_type)
        )
        db.session.add(indicator)
    else:
        indicator.count += 1
        indicator.last_seen = now
        indicator.enrichment = enrichment
        indicator.last_seen_attack = attack_type or indicator.last_seen_attack
        indicator.last_seen_stage = stage or indicator.last_seen_stage
        db.session.add(indicator)
    db.session.commit()
    return indicator

def _build_threat_summary(discoveries):
    lines = []
    for d in discoveries[:5]:
        sample = d.sample or {}
        line = f"- {sample.get('attack_type') or 'Unknown'} at {sample.get('stage') or sample.get('kill_chain_stage')}: {sample.get('tool') or 'Unknown tool'}"
        lines.append(line)
    if not lines:
        return "No new threats discovered."
    return "New threat patterns observed:\n" + "\n".join(lines)

def _build_threat_advisories(discoveries, max_items=6):
    grouped = {}
    for d in discoveries:
        sample = d.sample or {}
        attack_type = sample.get("attack_type") or "Unknown"
        stage = sample.get("stage") or sample.get("kill_chain_stage") or "Unknown"
        status_value = (sample.get("status") or ("Detected" if sample.get("detected") else "Missed")).strip().lower()
        key = f"{attack_type}|{stage}"
        if key not in grouped:
            grouped[key] = {
                "attack_type": attack_type,
                "stage": stage,
                "total": 0,
                "missed": 0,
                "tools": Counter(),
                "sources": Counter()
            }
        g = grouped[key]
        g["total"] += 1
        if status_value == "missed":
            g["missed"] += 1
        if sample.get("tool"):
            g["tools"][sample.get("tool")] += 1
        g["sources"][d.source or "unknown"] += 1

    if not grouped:
        return []

    advisories = []
    for g in grouped.values():
        miss_rate = (g["missed"] / g["total"]) if g["total"] else 0.0
        if g["missed"] >= 4 or (g["total"] >= 3 and miss_rate >= 0.75):
            priority = "critical"
        elif g["missed"] >= 2 or (g["total"] >= 3 and miss_rate >= 0.5):
            priority = "high"
        else:
            priority = "medium"

        top_tool = g["tools"].most_common(1)[0][0] if g["tools"] else "multiple tools"
        source_text = ", ".join([f"{k}:{v}" for k, v in g["sources"].most_common(2)])
        stage_recs = recommendations_map.get(g["stage"], {})
        actions = [
            stage_recs.get("improve") or "Harden control coverage for this stage.",
            stage_recs.get("response") or "Run immediate containment and verification playbooks."
        ]

        advisory_key = hashlib.sha256(
            json.dumps(
                {"attack_type": g["attack_type"], "stage": g["stage"]},
                sort_keys=True
            ).encode("utf-8")
        ).hexdigest()

        advisories.append({
            "advisory_key": advisory_key,
            "title": f"{g['attack_type']} exposure at {g['stage']}",
            "priority": priority,
            "summary": (
                f"Observed {g['total']} related signals with {g['missed']} misses "
                f"({int(miss_rate * 100)}% miss rate). Most common tooling: {top_tool}. "
                f"Primary sources: {source_text or 'unknown'}."
            ),
            "recommended_actions": actions,
            "signal_count": g["total"]
        })

    order = {"critical": 0, "high": 1, "medium": 2}
    advisories.sort(key=lambda a: (order.get(a["priority"], 9), -a["signal_count"]))
    return advisories[:max_items]

def _build_advisory_trend(advisories, days=7):
    today = datetime.utcnow().date()
    labels = []
    values = []
    for d in range(days - 1, -1, -1):
        day = today - timedelta(days=d)
        labels.append(day.strftime("%m-%d"))
        values.append(0)
    idx = {label: i for i, label in enumerate(labels)}
    for advisory in advisories:
        created = advisory.created_at.date() if advisory.created_at else today
        label = created.strftime("%m-%d")
        if label in idx:
            values[idx[label]] += 1
    return {"labels": labels, "values": values}

# --- Routes ---
@app.before_request
def init_session():
    if 'budget' not in session: session['budget'] = int(os.getenv('INITIAL_BUDGET', 5000))
    if 'upgrades' not in session: session['upgrades'] = {s[0]: 0.0 for s in kill_chain_data}
    if 'upgrades_purchased' not in session: session['upgrades_purchased'] = {}
    if 'history' not in session: session['history'] = []
    if 'user_id' not in session: session['user_id'] = None
    if 'data_source' not in session: session['data_source'] = 'both'

@app.before_request
def create_tables():
    """Create database tables on startup"""
    with app.app_context():
        db.create_all()
        _ensure_schema()
        try:
            if RetentionPolicy.query.count() == 0:
                db.session.add(RetentionPolicy())
                db.session.commit()
            if ThreatSettings.query.count() == 0:
                db.session.add(ThreatSettings())
                db.session.commit()
        except Exception as e:
            print(f"Retention policy init failed: {e}")
            db.session.rollback()
        _start_scheduler_once()

_scheduler_started = False
_scheduler = None

def _start_scheduler_once():
    global _scheduler_started, _scheduler
    if _scheduler_started:
        return
    _scheduler_started = True
    if APSCHEDULER_AVAILABLE:
        _scheduler = BackgroundScheduler()
        _scheduler.add_job(_background_retention_job, "interval", hours=24, id="retention_job")
        _scheduler.add_job(_background_schedule_job, "interval", minutes=1, id="schedule_job")
        _scheduler.add_job(_background_threat_summary_job, "interval", hours=6, id="threat_summary_job")
        _scheduler.add_job(lambda: app.app_context().push() or _check_case_sla(), "interval", minutes=15, id="case_sla_job")
        _scheduler.start()
    else:
        print("Warning: APScheduler not installed. Background scheduling disabled.")

_schema_checked = False

def _ensure_schema():
    """Lightweight SQLite migrations for new columns/tables."""
    global _schema_checked
    if _schema_checked:
        return
    _schema_checked = True

    if not app.config.get('SQLALCHEMY_DATABASE_URI', '').startswith('sqlite'):
        return

    def _table_columns(table):
        rows = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return {r[1] for r in rows}

    # Add missing columns
    try:
        user_cols = _table_columns("users")
        if "role" not in user_cols:
            db.session.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'viewer'"))

        sim_cols = _table_columns("simulations")
        if "tags" not in sim_cols:
            db.session.execute(text("ALTER TABLE simulations ADD COLUMN tags JSON"))
        if "variant" not in sim_cols:
            db.session.execute(text("ALTER TABLE simulations ADD COLUMN variant VARCHAR(20)"))

        # Saved searches table & column migration
        tables = {r[0] for r in db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "saved_searches" not in tables:
            db.session.execute(text(
                "CREATE TABLE saved_searches ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "name VARCHAR(80) NOT NULL, "
                "query_text VARCHAR(200) NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))
        else:
            ss_cols = _table_columns("saved_searches")
            if "query_text" not in ss_cols:
                db.session.execute(text("ALTER TABLE saved_searches ADD COLUMN query_text VARCHAR(200)"))
                if "query" in ss_cols:
                    db.session.execute(text("UPDATE saved_searches SET query_text = query WHERE query_text IS NULL"))

        if "simulation_presets" not in tables:
            db.session.execute(text(
                "CREATE TABLE simulation_presets ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "name VARCHAR(80) NOT NULL, "
                "attack_type VARCHAR(50) NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "simulation_schedules" not in tables:
            db.session.execute(text(
                "CREATE TABLE simulation_schedules ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "preset_id INTEGER NOT NULL, "
                "interval_minutes INTEGER DEFAULT 60, "
                "last_run_at DATETIME, "
                "enabled BOOLEAN DEFAULT 1, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id), "
                "FOREIGN KEY(preset_id) REFERENCES simulation_presets(id))"
            ))

        if "cases" not in tables:
            db.session.execute(text(
                "CREATE TABLE cases ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "simulation_id INTEGER, "
                "title VARCHAR(120) NOT NULL, "
                "description TEXT, "
                "status VARCHAR(20) DEFAULT 'Open', "
                "severity VARCHAR(20) DEFAULT 'Low', "
                "sla_hours INTEGER DEFAULT 48, "
                "escalated BOOLEAN DEFAULT 0, "
                "assignee_id INTEGER, "
                "created_at DATETIME, "
                "updated_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id), "
                "FOREIGN KEY(simulation_id) REFERENCES simulations(id), "
                "FOREIGN KEY(assignee_id) REFERENCES users(id))"
            ))
        else:
            case_cols = _table_columns("cases")
            if "sla_hours" not in case_cols:
                db.session.execute(text("ALTER TABLE cases ADD COLUMN sla_hours INTEGER DEFAULT 48"))
            if "escalated" not in case_cols:
                db.session.execute(text("ALTER TABLE cases ADD COLUMN escalated BOOLEAN DEFAULT 0"))

        if "case_notes" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_notes ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "author_id INTEGER NOT NULL, "
                "note TEXT NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id), "
                "FOREIGN KEY(author_id) REFERENCES users(id))"
            ))

        if "case_attachments" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_attachments ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "filename VARCHAR(200) NOT NULL, "
                "stored_path VARCHAR(300) NOT NULL, "
                "content_type VARCHAR(100), "
                "size_bytes INTEGER, "
                "uploaded_by INTEGER, "
                "created_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id), "
                "FOREIGN KEY(uploaded_by) REFERENCES users(id))"
            ))

        if "case_events" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_events ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "actor_id INTEGER, "
                "action VARCHAR(120) NOT NULL, "
                "meta JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id), "
                "FOREIGN KEY(actor_id) REFERENCES users(id))"
            ))

        if "case_checklist_items" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_checklist_items ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "framework VARCHAR(20) NOT NULL, "
                "item VARCHAR(200) NOT NULL, "
                "status VARCHAR(20) DEFAULT 'open', "
                "updated_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id))"
            ))

        if "audit_logs" not in tables:
            db.session.execute(text(
                "CREATE TABLE audit_logs ("
                "id INTEGER PRIMARY KEY, "
                "actor_id INTEGER, "
                "action VARCHAR(120) NOT NULL, "
                "meta JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(actor_id) REFERENCES users(id))"
            ))

        if "retention_policies" not in tables:
            db.session.execute(text(
                "CREATE TABLE retention_policies ("
                "id INTEGER PRIMARY KEY, "
                "simulations_days INTEGER DEFAULT 90, "
                "audit_days INTEGER DEFAULT 180, "
                "live_logs_days INTEGER DEFAULT 30, "
                "enabled BOOLEAN DEFAULT 1, "
                "updated_at DATETIME)"
            ))
        else:
            retention_cols = _table_columns("retention_policies")
            if "live_logs_days" not in retention_cols:
                db.session.execute(text("ALTER TABLE retention_policies ADD COLUMN live_logs_days INTEGER DEFAULT 30"))

        if "threat_signatures" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_signatures ("
                "id INTEGER PRIMARY KEY, "
                "fingerprint VARCHAR(64) UNIQUE NOT NULL, "
                "label VARCHAR(120), "
                "count INTEGER DEFAULT 1, "
                "first_seen DATETIME, "
                "last_seen DATETIME, "
                "status VARCHAR(20) DEFAULT 'new')"
            ))

        if "threat_discoveries" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_discoveries ("
                "id INTEGER PRIMARY KEY, "
                "signature_id INTEGER NOT NULL, "
                "source VARCHAR(20), "
                "sample JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(signature_id) REFERENCES threat_signatures(id))"
            ))

        if "threat_summaries" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_summaries ("
                "id INTEGER PRIMARY KEY, "
                "summary TEXT NOT NULL, "
                "created_at DATETIME)"
            ))

        if "threat_advisories" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_advisories ("
                "id INTEGER PRIMARY KEY, "
                "advisory_key VARCHAR(64) UNIQUE NOT NULL, "
                "title VARCHAR(160) NOT NULL, "
                "priority VARCHAR(20) DEFAULT 'medium', "
                "summary TEXT NOT NULL, "
                "recommended_actions JSON, "
                "signal_count INTEGER DEFAULT 0, "
                "status VARCHAR(20) DEFAULT 'open', "
                "created_at DATETIME, "
                "updated_at DATETIME)"
            ))

        if "threat_settings" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_settings ("
                "id INTEGER PRIMARY KEY, "
                "anomaly_threshold INTEGER DEFAULT 2, "
                "auto_case BOOLEAN DEFAULT 1, "
                "updated_at DATETIME)"
            ))

        if "user_widgets" not in tables:
            db.session.execute(text(
                "CREATE TABLE user_widgets ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "widget_key VARCHAR(50) NOT NULL, "
                "enabled BOOLEAN DEFAULT 1, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "indicators" not in tables:
            db.session.execute(text(
                "CREATE TABLE indicators ("
                "id INTEGER PRIMARY KEY, "
                "indicator_type VARCHAR(20) NOT NULL, "
                "value VARCHAR(80) NOT NULL, "
                "enrichment JSON, "
                "confidence FLOAT DEFAULT 0.5, "
                "status VARCHAR(20) DEFAULT 'new', "
                "source VARCHAR(30) DEFAULT 'log', "
                "last_seen_attack VARCHAR(50), "
                "last_seen_stage VARCHAR(50), "
                "count INTEGER DEFAULT 1, "
                "first_seen DATETIME, "
                "last_seen DATETIME, "
                "expires_at DATETIME)"
            ))
        else:
            ind_cols = _table_columns("indicators")
            if "confidence" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN confidence FLOAT DEFAULT 0.5"))
            if "status" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN status VARCHAR(20) DEFAULT 'new'"))
            if "source" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN source VARCHAR(30) DEFAULT 'log'"))
            if "last_seen_attack" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN last_seen_attack VARCHAR(50)"))
            if "last_seen_stage" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN last_seen_stage VARCHAR(50)"))
            if "expires_at" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN expires_at DATETIME"))

        if "indicator_relations" not in tables:
            db.session.execute(text(
                "CREATE TABLE indicator_relations ("
                "id INTEGER PRIMARY KEY, "
                "indicator_id INTEGER NOT NULL, "
                "relation_type VARCHAR(30) NOT NULL, "
                "relation_id VARCHAR(120) NOT NULL, "
                "meta JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(indicator_id) REFERENCES indicators(id))"
            ))

        if "alert_rules" not in tables:
            db.session.execute(text(
                "CREATE TABLE alert_rules ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER, "
                "name VARCHAR(80) NOT NULL, "
                "enabled BOOLEAN DEFAULT 1, "
                "attack_type VARCHAR(50), "
                "stage VARCHAR(50), "
                "status VARCHAR(20) DEFAULT 'Missed', "
                "severity_threshold VARCHAR(20) DEFAULT 'medium', "
                "auto_case BOOLEAN DEFAULT 0, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "live_filters" not in tables:
            db.session.execute(text(
                "CREATE TABLE live_filters ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "name VARCHAR(80) NOT NULL, "
                "filters JSON NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "live_logs" not in tables:
            db.session.execute(text(
                "CREATE TABLE live_logs ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER, "
                "raw_log JSON NOT NULL, "
                "mapped_event JSON, "
                "payload JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "feature_module_settings" not in tables:
            db.session.execute(text(
                "CREATE TABLE feature_module_settings ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "module_id VARCHAR(80) NOT NULL, "
                "settings JSON NOT NULL, "
                "updated_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        db.session.commit()
    except Exception as e:
        print(f"Schema ensure failed: {e}")
        db.session.rollback()

@app.route("/")
def dashboard():
    user_id = session.get('user_id')
    
    # Redirect to login if not authenticated
    if not user_id:
        return redirect(url_for('login'))

    # Support dashboard filtering via ?filter_stage=analyzed|found|created
    filter_stage = request.args.get('filter_stage')
    source_override = (request.args.get('data_source') or "").strip().lower()
    if source_override in ("live", "simulation", "both"):
        session['data_source'] = source_override
        session.modified = True
    timeline_days = int(request.args.get('timeline_days', 30))

    _run_due_schedules(user_id)

    history = _build_history(user_id)
    filtered_history = history
    if filter_stage:
        fs = (filter_stage or '').lower()
        if fs == 'created':
            filtered_history = [h for h in history if h.get('weakest')]
        elif fs == 'found':
            def has_detected(h):
                evs = h.get('events') or []
                if evs:
                    return any(e.get('status') == 'Detected' for e in evs)
                return int(h.get('score', 0)) > 0
            filtered_history = [h for h in history if has_detected(h)]
        else:
            filtered_history = history

    analytics = calculate_analytics(user_id, history_override=filtered_history, timeline_days=timeline_days)
    roi_data = calculate_upgrade_roi()
    saved_searches = SavedSearch.query.filter_by(user_id=user_id).order_by(SavedSearch.created_at.desc()).all()
    presets = SimulationPreset.query.filter_by(user_id=user_id).order_by(SimulationPreset.created_at.desc()).all()
    schedules = SimulationSchedule.query.filter_by(user_id=user_id).order_by(SimulationSchedule.created_at.desc()).all()
    preset_lookup = {p.id: p for p in presets}
    
    try:
        user = User.query.get(user_id)
    except Exception:
        user = None
    
    return render_template("dashboard.html", 
                           budget=session['budget'], 
                           upgrades=session['upgrades'], 
                           available_upgrades=UPGRADES, 
                           history=filtered_history,
                           analytics=analytics,
                           roi_data=roi_data,
                           incident_playbooks=incident_playbooks,
                           user=user,
                           ai_enabled=AI_ENABLED,
                           last_sim_id=session.get('last_sim_id'),
                           filter_stage=filter_stage,
                           search_query=request.args.get('q'),
                           search_results=None,
                           saved_searches=saved_searches,
                           presets=presets,
                           schedules=schedules,
                           preset_lookup=preset_lookup,
                           timeline_days=timeline_days,
                           cases=Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(10).all(),
                           users=User.query.order_by(User.username.asc()).all(),
                           widgets=_get_widget_prefs(user_id))

@app.route("/search")
def search():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    query = (request.args.get('q') or "").strip()
    if not query:
        return redirect(url_for('dashboard'))

    history = _build_history(user_id)
    timeline_days = int(request.args.get('timeline_days', 30))
    analytics = calculate_analytics(user_id, history_override=history, timeline_days=timeline_days)
    roi_data = calculate_upgrade_roi()
    results = search_all(query, user_id=user_id, limit=25)
    saved_searches = SavedSearch.query.filter_by(user_id=user_id).order_by(SavedSearch.created_at.desc()).all()
    presets = SimulationPreset.query.filter_by(user_id=user_id).order_by(SimulationPreset.created_at.desc()).all()
    schedules = SimulationSchedule.query.filter_by(user_id=user_id).order_by(SimulationSchedule.created_at.desc()).all()
    preset_lookup = {p.id: p for p in presets}

    try:
        user = User.query.get(user_id)
    except Exception:
        user = None

    return render_template(
        "dashboard.html",
        budget=session['budget'],
        upgrades=session['upgrades'],
        available_upgrades=UPGRADES,
        history=history,
        analytics=analytics,
        roi_data=roi_data,
        incident_playbooks=incident_playbooks,
        user=user,
        ai_enabled=AI_ENABLED,
        last_sim_id=session.get('last_sim_id'),
        filter_stage=None,
        search_query=query,
        search_results=results,
        saved_searches=saved_searches,
        presets=presets,
        schedules=schedules,
        preset_lookup=preset_lookup,
        timeline_days=timeline_days,
        cases=Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(10).all(),
        users=User.query.order_by(User.username.asc()).all(),
        widgets=_get_widget_prefs(user_id)
    )


@app.route("/presets")
def presets_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    presets = SimulationPreset.query.filter_by(user_id=user_id).order_by(SimulationPreset.created_at.desc()).all()
    schedules = SimulationSchedule.query.filter_by(user_id=user_id).order_by(SimulationSchedule.created_at.desc()).all()
    preset_lookup = {p.id: p for p in presets}
    return render_template("presets.html", presets=presets, schedules=schedules, preset_lookup=preset_lookup)


@app.route("/cases")
def cases_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    history = _build_history(user_id)
    cases = Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).all()
    users = User.query.order_by(User.username.asc()).all()
    return render_template("cases.html", cases=cases, history=history, users=users)


@app.route("/threats")
def threats_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    signatures = ThreatSignature.query.order_by(ThreatSignature.last_seen.desc()).limit(50).all()
    discoveries = ThreatDiscovery.query.order_by(ThreatDiscovery.created_at.desc()).limit(50).all()
    summaries = ThreatSummary.query.order_by(ThreatSummary.created_at.desc()).limit(5).all()
    return render_template("threats.html", signatures=signatures, discoveries=discoveries, summaries=summaries)


@app.route("/threats/advisories")
def threat_advisory_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    advisories = ThreatAdvisory.query.order_by(ThreatAdvisory.updated_at.desc()).limit(50).all()
    recent = advisories[:6]

    priority_counter = Counter([(a.priority or "medium").lower() for a in advisories])
    status_counter = Counter([(a.status or "open").lower() for a in advisories])
    trend = _build_advisory_trend(advisories, days=7)

    priority_labels = ["critical", "high", "medium"]
    priority_values = [priority_counter.get(k, 0) for k in priority_labels]
    status_labels = ["open", "applied", "dismissed"]
    status_values = [status_counter.get(k, 0) for k in status_labels]

    return render_template(
        "threat_advisories.html",
        advisories=advisories,
        recent_advisories=recent,
        priority_labels=priority_labels,
        priority_values=priority_values,
        status_labels=status_labels,
        status_values=status_values,
        trend=trend,
        total_advisories=len(advisories),
        total_open=status_counter.get("open", 0),
        total_applied=status_counter.get("applied", 0),
        total_dismissed=status_counter.get("dismissed", 0)
    )


@app.route("/threats/mark/<int:signature_id>", methods=["POST"])
def mark_threat(signature_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    status = (request.form.get("status") or "reviewed").strip()
    sig = ThreatSignature.query.get(signature_id)
    if sig and status in ("new", "reviewed", "ignored"):
        sig.status = status
        db.session.add(sig)
        db.session.commit()
        _record_audit(user_id, "threat_marked", {"signature_id": signature_id, "status": status})
    return redirect(url_for('threats_page'))


@app.route("/threats/summary", methods=["POST"])
def run_threat_summary():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    discoveries = ThreatDiscovery.query.order_by(ThreatDiscovery.created_at.desc()).limit(20).all()
    if discoveries:
        data = [{"source": d.source, "sample": d.sample} for d in discoveries]
        if AI_ENABLED:
            summary = ai_advisor.generate_threat_summary(data)
        else:
            summary = _build_threat_summary(discoveries)
        db.session.add(ThreatSummary(summary=summary))
        db.session.commit()
        _record_audit(user_id, "threat_summary_run", {"count": len(discoveries)})
    return redirect(url_for('threats_page'))


@app.route("/threats/advisories/generate", methods=["POST"])
def generate_threat_advisories():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    discoveries = ThreatDiscovery.query.order_by(ThreatDiscovery.created_at.desc()).limit(120).all()
    advisories = _build_threat_advisories(discoveries)
    now = datetime.utcnow()

    created = 0
    updated = 0
    for adv in advisories:
        existing = ThreatAdvisory.query.filter_by(advisory_key=adv["advisory_key"]).first()
        if existing:
            existing.title = adv["title"]
            existing.priority = adv["priority"]
            existing.summary = adv["summary"]
            existing.recommended_actions = adv["recommended_actions"]
            existing.signal_count = adv["signal_count"]
            existing.updated_at = now
            db.session.add(existing)
            updated += 1
        else:
            db.session.add(ThreatAdvisory(
                advisory_key=adv["advisory_key"],
                title=adv["title"],
                priority=adv["priority"],
                summary=adv["summary"],
                recommended_actions=adv["recommended_actions"],
                signal_count=adv["signal_count"],
                status="open",
                created_at=now,
                updated_at=now
            ))
            created += 1

    db.session.commit()
    _record_audit(user_id, "threat_advisories_generated", {"created": created, "updated": updated, "source_count": len(discoveries)})
    return redirect(url_for('threats_page'))


@app.route("/threats/advisories/<int:advisory_id>/status", methods=["POST"])
def update_threat_advisory_status(advisory_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    status = (request.form.get("status") or "open").strip().lower()
    if status not in ("open", "applied", "dismissed"):
        status = "open"

    advisory = ThreatAdvisory.query.get(advisory_id)
    if advisory:
        advisory.status = status
        advisory.updated_at = datetime.utcnow()
        db.session.add(advisory)
        db.session.commit()
        _record_audit(user_id, "threat_advisory_status_updated", {"advisory_id": advisory_id, "status": status})
    return redirect(url_for('threats_page'))


@app.route("/settings")
def settings_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    prefs = _get_widget_prefs(user_id)
    settings = ThreatSettings.query.first()
    rules = AlertRule.query.filter(or_(AlertRule.user_id == user_id, AlertRule.user_id.is_(None))).order_by(AlertRule.created_at.desc()).all()
    return render_template("settings.html", prefs=prefs, settings=settings, alert_rules=rules, data_source=session.get('data_source', 'both'))


@app.route("/settings/widgets", methods=["POST"])
def update_widgets():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    keys = ["analytics", "summary", "history", "search_results"]
    selected = set(request.form.getlist("widgets"))
    UserWidget.query.filter_by(user_id=user_id).delete()
    for k in keys:
        db.session.add(UserWidget(user_id=user_id, widget_key=k, enabled=(k in selected)))
    db.session.commit()
    _record_audit(user_id, "widgets_updated", {"enabled": list(selected)})
    return redirect(url_for('settings_page'))


@app.route("/settings/threats", methods=["POST"])
def update_threat_settings():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    threshold = (request.form.get("anomaly_threshold") or "").strip()
    auto_case = request.form.get("auto_case") == "on"
    settings = ThreatSettings.query.first()
    if not settings:
        settings = ThreatSettings()
    if threshold.isdigit():
        settings.anomaly_threshold = int(threshold)
    settings.auto_case = auto_case
    db.session.add(settings)
    db.session.commit()
    _record_audit(user_id, "threat_settings_updated", {"anomaly_threshold": settings.anomaly_threshold, "auto_case": settings.auto_case})
    return redirect(url_for('settings_page'))

@app.route("/settings/data-source", methods=["POST"])
def update_data_source():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    source = (request.form.get("data_source") or "both").strip().lower()
    if source not in ("live", "simulation", "both"):
        source = "live"
    session['data_source'] = source
    session.modified = True
    _record_audit(user_id, "data_source_updated", {"data_source": source})
    return redirect(url_for('settings_page'))

@app.route("/settings/alerts", methods=["POST"])
def create_alert_rule():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Alert rule name is required.", "error")
        return redirect(url_for('settings_page'))
    rule = AlertRule(
        user_id=user_id,
        name=name,
        attack_type=(request.form.get("attack_type") or "").strip() or None,
        stage=(request.form.get("stage") or "").strip() or None,
        status=(request.form.get("status") or "Missed").strip(),
        severity_threshold=(request.form.get("severity_threshold") or "medium").strip().lower(),
        auto_case=request.form.get("auto_case") == "on",
        enabled=True
    )
    db.session.add(rule)
    db.session.commit()
    _record_audit(user_id, "alert_rule_created", {"rule_id": rule.id})
    return redirect(url_for('settings_page'))

@app.route("/settings/alerts/toggle/<int:rule_id>", methods=["POST"])
def toggle_alert_rule(rule_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    rule = AlertRule.query.filter_by(id=rule_id, user_id=user_id).first()
    if rule:
        rule.enabled = not rule.enabled
        db.session.add(rule)
        db.session.commit()
    return redirect(url_for('settings_page'))

@app.route("/settings/alerts/delete/<int:rule_id>", methods=["POST"])
def delete_alert_rule(rule_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    rule = AlertRule.query.filter_by(id=rule_id, user_id=user_id).first()
    if rule:
        db.session.delete(rule)
        db.session.commit()
        _record_audit(user_id, "alert_rule_deleted", {"rule_id": rule_id})
    return redirect(url_for('settings_page'))


@app.route("/audit")
@_require_roles("admin", "analyst")
def audit_page():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template("audit.html", logs=logs)


@app.route("/intel")
@_require_roles("admin", "analyst")
def intel_page():
    indicators = Indicator.query.order_by(Indicator.last_seen.desc()).limit(200).all()
    relations = IndicatorRelation.query.order_by(IndicatorRelation.created_at.desc()).limit(200).all()
    return render_template("intel.html", indicators=indicators, relations=relations)

@app.route("/rule-effectiveness")
@_require_roles("admin", "analyst")
def rule_effectiveness_page():
    user_id = session.get('user_id')
    metrics = _compute_rule_effectiveness(user_id, lookback_days=30, trend_days=14)
    rules = metrics.get("rules") or []

    selected_rule_id = request.args.get("rule_id", type=int)
    if not selected_rule_id and rules:
        selected_rule_id = rules[0]["id"]

    selected_rule = next((r for r in rules if r["id"] == selected_rule_id), None)
    if not selected_rule and rules:
        selected_rule = rules[0]

    return render_template(
        "rule_effectiveness.html",
        rules=rules,
        top_noisy=metrics.get("top_noisy") or [],
        event_count=metrics.get("event_count") or 0,
        trend_labels=metrics.get("trend_labels") or [],
        selected_rule=selected_rule
    )

FEATURE_MODULES = {
    "rule-tuning": {
        "title": "Rule Tuning Assistant",
        "summary": "Suggest threshold, stage, and status changes based on FP/TP trends.",
        "settings": [
            {"key": "noise_floor_fp", "label": "Noise Floor FP", "type": "number", "default": 8},
            {"key": "min_precision", "label": "Minimum Precision %", "type": "number", "default": 70},
            {"key": "auto_suggest", "label": "Enable Auto Suggestions", "type": "bool", "default": True}
        ]
    },
    "case-similarity": {
        "title": "Case Similarity Engine",
        "summary": "Find related historical cases by attack, stage, and IOC overlap.",
        "settings": [
            {"key": "top_k", "label": "Top Similar Cases", "type": "number", "default": 5},
            {"key": "ioc_weight", "label": "IOC Similarity Weight", "type": "number", "default": 60},
            {"key": "stage_weight", "label": "Stage Similarity Weight", "type": "number", "default": 40}
        ]
    },
    "mitre-planner": {
        "title": "MITRE Coverage Planner",
        "summary": "Prioritize uncovered techniques and map recommended controls.",
        "settings": [
            {"key": "priority_scope", "label": "Priority Scope", "type": "select", "default": "top10", "options": ["top5", "top10", "top20"]},
            {"key": "include_detected", "label": "Include Detected Techniques", "type": "bool", "default": False},
            {"key": "focus_stage", "label": "Focus Stage", "type": "select", "default": "all", "options": ["all", "Reconnaissance", "Delivery", "Exploitation", "Installation", "Command & Control", "Actions on Objectives"]}
        ]
    },
    "sla-heatmap": {
        "title": "Response SLA Heatmap",
        "summary": "Track SLA breaches by team, severity, and kill-chain stage.",
        "settings": [
            {"key": "sla_hours_default", "label": "Default SLA Hours", "type": "number", "default": 48},
            {"key": "severity_filter", "label": "Severity Filter", "type": "select", "default": "all", "options": ["all", "Low", "Medium", "High", "Critical"]},
            {"key": "show_only_breached", "label": "Show Only Breached Cases", "type": "bool", "default": False}
        ]
    },
    "emulation-packs": {
        "title": "Adversary Emulation Packs",
        "summary": "Run scenario bundles and benchmark performance across runs.",
        "settings": [
            {"key": "pack_profile", "label": "Pack Profile", "type": "select", "default": "balanced", "options": ["balanced", "stealthy", "noisy", "fast"]},
            {"key": "iterations", "label": "Iterations per Pack", "type": "number", "default": 3},
            {"key": "include_live_data", "label": "Include Live Data Baseline", "type": "bool", "default": True}
        ]
    },
    "timeline-generator": {
        "title": "Post-Incident Timeline Generator",
        "summary": "Auto-build forensic timelines from logs, alerts, and case notes.",
        "settings": [
            {"key": "window_hours", "label": "Timeline Window (hours)", "type": "number", "default": 72},
            {"key": "include_notes", "label": "Include Case Notes", "type": "bool", "default": True},
            {"key": "include_iocs", "label": "Include IOC Events", "type": "bool", "default": True}
        ]
    },
    "intel-confidence": {
        "title": "Threat Intel Confidence Scoring",
        "summary": "Score IOC confidence from source quality, recurrence, and context.",
        "settings": [
            {"key": "min_confidence", "label": "Minimum Confidence", "type": "number", "default": 50},
            {"key": "source_weight", "label": "Source Quality Weight", "type": "number", "default": 40},
            {"key": "recurrence_weight", "label": "Recurrence Weight", "type": "number", "default": 60}
        ]
    },
    "executive-snapshot": {
        "title": "Executive Risk Snapshot",
        "summary": "One-page board summary of risk, gaps, trends, and response KPIs.",
        "settings": [
            {"key": "report_range_days", "label": "Report Range (days)", "type": "number", "default": 30},
            {"key": "risk_model", "label": "Risk Model", "type": "select", "default": "balanced", "options": ["balanced", "aggressive", "conservative"]},
            {"key": "include_top_noisy", "label": "Include Top Noisy Rules", "type": "bool", "default": True}
        ]
    },
    "data-quality": {
        "title": "Data Quality Monitor",
        "summary": "Detect ingestion gaps, malformed events, and schema drift early.",
        "settings": [
            {"key": "missing_field_threshold", "label": "Missing Field Threshold %", "type": "number", "default": 5},
            {"key": "schema_drift_alert", "label": "Alert on Schema Drift", "type": "bool", "default": True},
            {"key": "monitor_window_minutes", "label": "Monitor Window (minutes)", "type": "number", "default": 60}
        ]
    }
}

def _module_default_settings(module_id):
    module = FEATURE_MODULES.get(module_id) or {}
    fields = module.get("settings") or []
    defaults = {}
    for f in fields:
        defaults[f["key"]] = f.get("default")
    return defaults

def _module_settings_for_user(user_id, module_id):
    defaults = _module_default_settings(module_id)
    row = FeatureModuleSetting.query.filter_by(user_id=user_id, module_id=module_id).first()
    if not row or not isinstance(row.settings, dict):
        return defaults
    merged = defaults.copy()
    merged.update(row.settings)
    return merged

def _feature_module_preview(user_id, module_id, settings):
    history = _build_history(user_id)
    analytics = calculate_analytics(user_id, history_override=history, timeline_days=30)

    if module_id == "rule-tuning":
        metrics = _compute_rule_effectiveness(user_id, lookback_days=30, trend_days=14)
        min_precision = int(settings.get("min_precision", 70) or 70)
        noise_floor = int(settings.get("noise_floor_fp", 8) or 8)
        candidates = []
        for r in metrics.get("rules") or []:
            if r["precision"] < min_precision or r["fp"] >= noise_floor:
                suggestion = "Increase severity threshold"
                if r["fp"] >= noise_floor:
                    suggestion = "Narrow attack/stage scope"
                elif r["precision"] < min_precision:
                    suggestion = "Adjust status target or stage filter"
                candidates.append({
                    "rule": r["name"],
                    "precision": r["precision"],
                    "fp": r["fp"],
                    "suggestion": suggestion
                })
        return {"type": "table", "title": "Tuning Suggestions", "rows": candidates[:8]}

    if module_id == "case-similarity":
        rows = []
        recent_cases = Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(10).all()
        for c in recent_cases:
            sim = Simulation.query.get(c.simulation_id) if c.simulation_id else None
            attack = sim.attack_type if sim else "Unknown"
            similar = Case.query.filter(
                Case.user_id == user_id,
                Case.id != c.id,
                Case.simulation_id.isnot(None)
            ).order_by(Case.updated_at.desc()).limit(20).all()
            overlap = 0
            for s in similar:
                ssim = Simulation.query.get(s.simulation_id) if s.simulation_id else None
                if ssim and ssim.attack_type == attack:
                    overlap += 1
            rows.append({"case": c.title, "attack": attack, "similar_cases": overlap})
        return {"type": "table", "title": "Recent Case Similarity", "rows": rows[:8]}

    if module_id == "mitre-planner":
        coverage = analytics.get("mitre_coverage") or {}
        gaps = coverage.get("gaps") or []
        scope = settings.get("priority_scope", "top10")
        limit = 10
        if scope == "top5":
            limit = 5
        elif scope == "top20":
            limit = 20
        return {
            "type": "list",
            "title": "Priority MITRE Gaps",
            "items": gaps[:limit],
            "meta": f"Coverage: {coverage.get('coverage', 0)}%"
        }

    if module_id == "sla-heatmap":
        severity_filter = (settings.get("severity_filter") or "all").lower()
        only_breached = bool(settings.get("show_only_breached"))
        now = datetime.utcnow()
        rows = []
        cases = Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(200).all()
        for c in cases:
            sev = (c.severity or "low").lower()
            if severity_filter != "all" and sev != severity_filter:
                continue
            sla_deadline = (c.created_at or now) + timedelta(hours=int(c.sla_hours or settings.get("sla_hours_default", 48)))
            breached = now > sla_deadline and c.status not in ("Resolved", "Closed")
            if only_breached and not breached:
                continue
            rows.append({
                "case": c.title,
                "severity": c.severity,
                "status": c.status,
                "breached": "Yes" if breached else "No"
            })
        return {"type": "table", "title": "SLA Status", "rows": rows[:12]}

    if module_id == "emulation-packs":
        profile = settings.get("pack_profile", "balanced")
        iterations = int(settings.get("iterations", 3) or 3)
        atk = analytics.get("attack_breakdown") or {}
        top = sorted(atk.items(), key=lambda kv: kv[1])[:3]
        items = [f"{k}: baseline {v}%" for k, v in top]
        return {"type": "list", "title": f"Suggested Pack ({profile}, x{iterations})", "items": items}

    if module_id == "timeline-generator":
        window_hours = int(settings.get("window_hours", 72) or 72)
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        case = Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).first()
        if not case:
            return {"type": "list", "title": "Timeline Preview", "items": []}
        events = CaseEvent.query.filter(CaseEvent.case_id == case.id, CaseEvent.created_at >= cutoff).order_by(CaseEvent.created_at.asc()).limit(30).all()
        notes = CaseNote.query.filter(CaseNote.case_id == case.id, CaseNote.created_at >= cutoff).order_by(CaseNote.created_at.asc()).limit(20).all()
        items = [f"{e.created_at.strftime('%Y-%m-%d %H:%M')} - {e.action}" for e in events]
        if settings.get("include_notes"):
            items.extend([f"{n.created_at.strftime('%Y-%m-%d %H:%M')} - Note: {n.note[:80]}" for n in notes])
        items.sort()
        return {"type": "list", "title": f"Timeline for {case.title}", "items": items[:20]}

    if module_id == "intel-confidence":
        min_conf = int(settings.get("min_confidence", 50) or 50) / 100.0
        indicators = Indicator.query.order_by(Indicator.last_seen.desc()).limit(200).all()
        rows = []
        for i in indicators:
            source_score = 0.8 if (i.source or "") in ("log", "simulation") else 0.5
            recurrence = min((i.count or 1) / 10.0, 1.0)
            score = round(((source_score * float(settings.get("source_weight", 40))) + (recurrence * float(settings.get("recurrence_weight", 60)))) / 100.0, 2)
            if score >= min_conf:
                rows.append({"ioc": f"{i.indicator_type}:{i.value}", "score": int(score * 100), "count": i.count})
        rows.sort(key=lambda r: r["score"], reverse=True)
        return {"type": "table", "title": "High Confidence IOCs", "rows": rows[:12]}

    if module_id == "executive-snapshot":
        top_gap = (analytics.get("kill_chain_gaps") or [{}])[0]
        noisy = (_compute_rule_effectiveness(user_id).get("top_noisy") or [{}])[0]
        cards = [
            {"label": "Average Detection", "value": f"{analytics.get('avg_score', 0)}%"},
            {"label": "Total Simulations", "value": analytics.get("total_simulations", 0)},
            {"label": "Top Gap", "value": f"{top_gap.get('stage', 'N/A')} ({top_gap.get('count', 0)})"},
            {"label": "Top Noisy Rule", "value": noisy.get("name", "N/A")}
        ]
        return {"type": "cards", "title": "Executive Snapshot", "cards": cards}

    if module_id == "data-quality":
        window_minutes = int(settings.get("monitor_window_minutes", 60) or 60)
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        recent = [ev for ev in list(LIVE_EVENTS) if _parse_event_time(ev.get("ts")) and _parse_event_time(ev.get("ts")) >= cutoff]
        required = ["attack", "severity", "event", "timestamp"]
        total = len(recent) or 1
        missing = {k: 0 for k in required}
        for ev in recent:
            for k in required:
                if not ev.get(k):
                    missing[k] += 1
        rows = [{"field": k, "missing_pct": round((v / total) * 100, 1), "count": v} for k, v in missing.items()]
        return {"type": "table", "title": "Live Data Quality (Recent Window)", "rows": rows}

    return {"type": "list", "title": "Preview", "items": []}

@app.route("/feature-module/<module_id>")
@_require_roles("admin", "analyst")
def feature_module_page(module_id):
    module = FEATURE_MODULES.get(module_id)
    if not module:
        return redirect(url_for("dashboard"))
    user_id = session.get("user_id")
    current_settings = _module_settings_for_user(user_id, module_id)
    preview = _feature_module_preview(user_id, module_id, current_settings)
    return render_template("feature_module.html", module=module, module_id=module_id, current_settings=current_settings, preview=preview)

@app.route("/feature-module/<module_id>/settings", methods=["POST"])
@_require_roles("admin", "analyst")
def save_feature_module_settings(module_id):
    module = FEATURE_MODULES.get(module_id)
    if not module:
        return redirect(url_for("dashboard"))

    user_id = session.get("user_id")
    payload = {}
    for field in (module.get("settings") or []):
        key = field.get("key")
        ftype = field.get("type")
        default = field.get("default")
        if ftype == "bool":
            payload[key] = request.form.get(key) == "on"
        elif ftype == "number":
            raw = (request.form.get(key) or "").strip()
            try:
                payload[key] = int(raw) if raw else int(default or 0)
            except Exception:
                payload[key] = int(default or 0)
        elif ftype == "select":
            options = set(field.get("options") or [])
            value = (request.form.get(key) or "").strip()
            payload[key] = value if value in options else default
        else:
            value = (request.form.get(key) or "").strip()
            payload[key] = value if value else default

    row = FeatureModuleSetting.query.filter_by(user_id=user_id, module_id=module_id).first()
    if not row:
        row = FeatureModuleSetting(user_id=user_id, module_id=module_id, settings=payload)
    else:
        row.settings = payload
    db.session.add(row)
    db.session.commit()
    flash("Feature settings saved.", "success")
    return redirect(url_for("feature_module_page", module_id=module_id))

@app.route("/api/intel/graph")
@_require_roles("admin", "analyst")
def intel_graph():
    indicators = Indicator.query.order_by(Indicator.last_seen.desc()).limit(100).all()
    relations = IndicatorRelation.query.order_by(IndicatorRelation.created_at.desc()).limit(200).all()
    nodes = []
    edges = []
    for i in indicators:
        nodes.append({"id": f"ioc:{i.id}", "label": f"{i.indicator_type}:{i.value}"})
    for r in relations:
        edges.append({
            "from": f"ioc:{r.indicator_id}",
            "to": f"{r.relation_type}:{r.relation_id}",
            "label": r.relation_type
        })
    return jsonify({"nodes": nodes, "edges": edges})


@app.route("/activity")
@_require_roles("admin", "analyst")
def activity_page():
    users = User.query.order_by(User.username.asc()).all()
    rows = []
    for u in users:
        sims = Simulation.query.filter_by(user_id=u.id).all()
        scores = [s.detection_score for s in sims]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
        cases_created = Case.query.filter_by(user_id=u.id).count()
        cases_assigned = Case.query.filter_by(assignee_id=u.id).count()
        notes = CaseNote.query.filter_by(author_id=u.id).count()
        rows.append({
            "user": u,
            "avg_score": avg_score,
            "sim_count": len(scores),
            "cases_created": cases_created,
            "cases_assigned": cases_assigned,
            "notes": notes
        })
    return render_template("activity.html", rows=rows)

@app.route('/ai/insights', methods=['POST'])
def ai_insights():
    if not AI_ENABLED:
        return jsonify({'error': 'AI features not enabled on this instance.'}), 503
    payload = request.get_json() or {}
    panel = payload.get('panel')
    stage = (payload.get('stage') or '').lower()
    user_id = session.get('user_id')
    history = _build_history(user_id)

    try:
        if panel == 'funnel':
            # For funnel-level suggestions, map stage to a minimal context
            if stage == 'created':
                weakest = ['Actions on Objectives']
            elif stage == 'found':
                weakest = []
            else:
                weakest = []
            scores = [h.get('score', 0) for h in history]
            avg_score = int(sum(scores) / len(scores)) if scores else 0
            recs = ai_advisor.generate_intelligent_recommendations('All', avg_score, weakest, session.get('upgrades', {}))
            return jsonify({'recommendations': recs})
        elif panel == 'strategy':
            scores = [h.get('score', 0) for h in history]
            avg_score = sum(scores) / len(scores) if scores else 0
            total_spent = sum([UPGRADES[k]['cost'] * session.get('upgrades_purchased', {}).get(k, 0) for k in UPGRADES])
            narrative = ai_advisor.analyze_defense_strategy(len(history), avg_score, (calculate_analytics(user_id) or {}).get('attack_breakdown', {}), total_spent)
            return jsonify({'strategy': narrative})
        else:
            return jsonify({'error': 'Unsupported panel for AI insights'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ai/live/brief', methods=['POST'])
def ai_live_brief():
    payload = request.get_json() or {}
    events = payload.get('events') or []
    events = events[:50]
    if not AI_ENABLED:
        return jsonify({'summary': _build_live_brief(events), 'ai': False})
    try:
        summary = ai_advisor.summarize_live_events(events)
        return jsonify({'summary': summary, 'ai': True})
    except Exception as e:
        return jsonify({'summary': _build_live_brief(events), 'ai': False, 'error': str(e)})

@app.route('/ai/recommendations/explain', methods=['POST'])
def ai_explain_recommendations():
    payload = request.get_json() or {}
    attack_type = payload.get('attack_type')
    event = payload.get('event') or {}
    recommendations = payload.get('recommendations') or []
    if not AI_ENABLED:
        return jsonify({'explanation': _fallback_recommendation_explain(event, recommendations), 'ai': False})
    try:
        explanation = ai_advisor.explain_recommendations(attack_type, event, recommendations)
        return jsonify({'explanation': explanation, 'ai': True})
    except Exception as e:
        return jsonify({'explanation': _fallback_recommendation_explain(event, recommendations), 'ai': False, 'error': str(e)})

@app.route('/ai/next_steps', methods=['POST'])
def ai_next_steps():
    payload = request.get_json() or {}
    attack_type = payload.get('attack_type')
    event = payload.get('event') or {}
    if not AI_ENABLED:
        return jsonify({'steps': _fallback_next_steps(attack_type), 'ai': False})
    try:
        steps = ai_advisor.suggest_next_steps(attack_type, event, incident_playbooks.get(attack_type, {}))
        return jsonify({'steps': steps, 'ai': True})
    except Exception as e:
        return jsonify({'steps': _fallback_next_steps(attack_type), 'ai': False, 'error': str(e)})

@app.route('/ai/case_summary', methods=['POST'])
def ai_case_summary():
    payload = request.get_json() or {}
    case_id = payload.get("case_id")
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    case = Case.query.get(case_id) if case_id else None
    if not case or case.user_id != user_id:
        return jsonify({"error": "Case not found"}), 404
    notes = CaseNote.query.filter_by(case_id=case.id).order_by(CaseNote.created_at.desc()).all()
    sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
    if not AI_ENABLED:
        return jsonify({"summary": _fallback_case_summary(case, notes, sim), "ai": False})
    try:
        summary = ai_advisor.summarize_case(
            {
                "title": case.title,
                "description": case.description,
                "status": case.status,
                "severity": case.severity
            },
            [{"note": n.note, "created_at": n.created_at.isoformat()} for n in notes],
            {
                "attack_type": sim.attack_type,
                "detection_score": sim.detection_score,
                "events": sim.events,
                "weakest_stages": sim.weakest_stages
            } if sim else None
        )
        return jsonify({"summary": summary, "ai": True})
    except Exception as e:
        return jsonify({"summary": _fallback_case_summary(case, notes, sim), "ai": False, "error": str(e)})

@app.route('/ai/root_cause', methods=['POST'])
def ai_root_cause():
    payload = request.get_json() or {}
    case_id = payload.get("case_id")
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    case = Case.query.get(case_id) if case_id else None
    if not case or case.user_id != user_id:
        return jsonify({"error": "Case not found"}), 404
    sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
    events = sim.events if sim else []
    if not AI_ENABLED:
        return jsonify({"analysis": _fallback_root_cause(events), "ai": False})
    try:
        analysis = ai_advisor.analyze_root_cause(events)
        return jsonify({"analysis": analysis, "ai": True})
    except Exception as e:
        return jsonify({"analysis": _fallback_root_cause(events), "ai": False, "error": str(e)})

@app.route('/ai/triage_score', methods=['POST'])
def ai_triage_score():
    payload = request.get_json() or {}
    case_id = payload.get("case_id")
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    case = Case.query.get(case_id) if case_id else None
    if not case or case.user_id != user_id:
        return jsonify({"error": "Case not found"}), 404
    sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
    if not AI_ENABLED:
        return jsonify({"triage": _fallback_triage(case, sim), "ai": False})
    try:
        triage = ai_advisor.triage_score(
            {"title": case.title, "description": case.description, "status": case.status, "severity": case.severity},
            {
                "attack_type": sim.attack_type,
                "detection_score": sim.detection_score,
                "events": sim.events
            } if sim else None
        )
        return jsonify({"triage": triage, "ai": True})
    except Exception as e:
        return jsonify({"triage": _fallback_triage(case, sim), "ai": False, "error": str(e)})


@app.route("/search/save", methods=["POST"])
def save_search():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    name = (request.form.get("name") or "").strip()
    query = (request.form.get("query") or "").strip()
    if not name or not query:
        flash("Name and query are required to save a search.", "error")
        return redirect(url_for('search', q=query))
    try:
        db.session.add(SavedSearch(user_id=user_id, name=name, query_text=query))
        db.session.commit()
        flash("Search saved.", "success")
    except Exception as e:
        print(f"Save search error: {e}")
        db.session.rollback()
        flash("Failed to save search.", "error")
    return redirect(url_for('search', q=query))


@app.route("/search/delete/<int:search_id>", methods=["POST"])
def delete_search(search_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    search = SavedSearch.query.filter_by(id=search_id, user_id=user_id).first()
    if not search:
        return redirect(url_for('dashboard'))
    db.session.delete(search)
    db.session.commit()
    flash("Saved search removed.", "info")
    return redirect(url_for('dashboard'))


@app.route("/presets/create", methods=["POST"])
def create_preset():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    name = (request.form.get("name") or "").strip()
    attack_type = request.form.get("attack_type")
    if not name or not attack_type:
        flash("Preset name and attack type are required.", "error")
        return redirect(url_for('dashboard'))
    try:
        db.session.add(SimulationPreset(user_id=user_id, name=name, attack_type=attack_type))
        db.session.commit()
        flash("Preset created.", "success")
    except Exception as e:
        print(f"Create preset error: {e}")
        db.session.rollback()
        flash("Failed to create preset.", "error")
    return redirect(url_for('dashboard'))


@app.route("/presets/run/<int:preset_id>", methods=["POST"])
def run_preset(preset_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    preset = SimulationPreset.query.filter_by(id=preset_id, user_id=user_id).first()
    if not preset:
        return redirect(url_for('dashboard'))
    _run_simulation_for_user(preset.attack_type, user_id, source="preset")
    return redirect(url_for('dashboard'))


@app.route("/schedules/create", methods=["POST"])
def create_schedule():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    preset_raw = (request.form.get("preset_id") or "").strip()
    interval_raw = (request.form.get("interval_minutes") or "").strip()
    if not preset_raw:
        flash("Preset and interval are required.", "error")
        return redirect(url_for('dashboard'))
    try:
        preset_id = int(preset_raw)
        interval = int(interval_raw or 60)
    except ValueError:
        flash("Preset and interval must be valid numbers.", "error")
        return redirect(url_for('dashboard'))
    if preset_id <= 0 or interval <= 0:
        flash("Preset and interval are required.", "error")
        return redirect(url_for('dashboard'))
    preset = SimulationPreset.query.filter_by(id=preset_id, user_id=user_id).first()
    if not preset:
        flash("Preset not found.", "error")
        return redirect(url_for('dashboard'))
    try:
        db.session.add(SimulationSchedule(user_id=user_id, preset_id=preset_id, interval_minutes=interval))
        db.session.commit()
        flash("Schedule created. It runs when you access the dashboard.", "info")
    except Exception as e:
        print(f"Create schedule error: {e}")
        db.session.rollback()
        flash("Failed to create schedule.", "error")
    return redirect(url_for('dashboard'))


@app.route("/schedules/toggle/<int:schedule_id>", methods=["POST"])
def toggle_schedule(schedule_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    sched = SimulationSchedule.query.filter_by(id=schedule_id, user_id=user_id).first()
    if not sched:
        return redirect(url_for('dashboard'))
    sched.enabled = not sched.enabled
    db.session.add(sched)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route("/simulations/<int:sim_id>/tags", methods=["POST"])
def tag_simulation(sim_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    sim = Simulation.query.filter_by(id=sim_id, user_id=user_id).first()
    if not sim:
        return redirect(url_for('dashboard'))
    raw = (request.form.get("tags") or "").strip()
    tags = [t.strip() for t in raw.split(",") if t.strip()]
    if tags:
        current = sim.tags or []
        sim.tags = sorted(set(current + tags))
        db.session.add(sim)
        db.session.commit()
    return redirect(url_for('report', sim_id=sim_id))


@app.route("/cases/create", methods=["POST"])
def create_case():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    sim_id_raw = (request.form.get("simulation_id") or "").strip()
    assignee_id_raw = (request.form.get("assignee_id") or "").strip()
    status = (request.form.get("status") or "Open").strip()
    sla_raw = (request.form.get("sla_hours") or "").strip()
    template_attack = (request.form.get("template_attack") or "").strip()
    if not title:
        tpl = CASE_TEMPLATES.get(template_attack)
        if tpl:
            title = tpl["title"]
            if not description:
                description = tpl["description"]
            if not sla_raw:
                sla_raw = str(tpl.get("sla_hours") or "")
        else:
            flash("Case title is required.", "error")
            return redirect(url_for('dashboard'))

    sim_id = int(sim_id_raw) if sim_id_raw.isdigit() else None
    assignee_id = int(assignee_id_raw) if assignee_id_raw.isdigit() else None
    sla_hours = int(sla_raw) if sla_raw.isdigit() else 48
    severity = "Low"
    if sim_id:
        sim = Simulation.query.filter_by(id=sim_id, user_id=user_id).first()
        if sim:
            severity = _severity_from_score(sim.detection_score)
        else:
            sim_id = None
    if template_attack and CASE_TEMPLATES.get(template_attack):
        severity = CASE_TEMPLATES[template_attack].get("severity", severity)

    case = Case(
        user_id=user_id,
        simulation_id=sim_id,
        title=title,
        description=description,
        status=status,
        severity=severity,
        sla_hours=sla_hours,
        assignee_id=assignee_id
    )
    db.session.add(case)
    db.session.commit()
    _record_audit(user_id, "case_created", {"case_id": case.id, "sim_id": sim_id})
    _record_case_event(case.id, user_id, "case_created", {"template_attack": template_attack or None})
    return redirect(url_for('case_detail', case_id=case.id))


@app.route("/cases/<int:case_id>")
def case_detail(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at.desc()).all()
    attachments = CaseAttachment.query.filter_by(case_id=case_id).order_by(CaseAttachment.created_at.desc()).all()
    events = CaseEvent.query.filter_by(case_id=case_id).order_by(CaseEvent.created_at.desc()).all()
    _ensure_case_checklist(case.id)
    checklist = CaseChecklistItem.query.filter_by(case_id=case_id).order_by(CaseChecklistItem.framework.asc(), CaseChecklistItem.id.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
    return render_template("case_detail.html", case=case, notes=notes, users=users, sim=sim, attachments=attachments, events=events, checklist=checklist)


@app.route("/cases/<int:case_id>/update", methods=["POST"])
def update_case(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    case.status = (request.form.get("status") or case.status).strip()
    case.assignee_id = int(request.form.get("assignee_id")) if (request.form.get("assignee_id") or "").isdigit() else case.assignee_id
    case.description = (request.form.get("description") or case.description or "").strip()
    sla_raw = (request.form.get("sla_hours") or "").strip()
    if sla_raw.isdigit():
        case.sla_hours = int(sla_raw)
    db.session.add(case)
    db.session.commit()
    _record_audit(user_id, "case_updated", {"case_id": case.id, "status": case.status, "assignee_id": case.assignee_id})
    _record_case_event(case.id, user_id, "case_updated", {"status": case.status, "assignee_id": case.assignee_id})
    return redirect(url_for('case_detail', case_id=case.id))


@app.route("/cases/<int:case_id>/note", methods=["POST"])
def add_case_note(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    note = (request.form.get("note") or "").strip()
    if not note:
        return redirect(url_for('case_detail', case_id=case.id))
    db.session.add(CaseNote(case_id=case_id, author_id=user_id, note=note))
    db.session.commit()
    _record_audit(user_id, "case_note_added", {"case_id": case.id})
    _record_case_event(case.id, user_id, "case_note_added", {"note_preview": note[:120]})
    return redirect(url_for('case_detail', case_id=case.id))

@app.route("/cases/<int:case_id>/attachment", methods=["POST"])
def add_case_attachment(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    if 'file' not in request.files:
        flash("No file uploaded.", "error")
        return redirect(url_for('case_detail', case_id=case.id))
    f = request.files['file']
    if not f or not f.filename:
        flash("No file selected.", "error")
        return redirect(url_for('case_detail', case_id=case.id))
    filename = secure_filename(f.filename)
    base_dir = os.path.join(app.instance_path, "uploads", "cases", str(case.id))
    os.makedirs(base_dir, exist_ok=True)
    stored_path = os.path.join(base_dir, filename)
    f.save(stored_path)
    attachment = CaseAttachment(
        case_id=case.id,
        filename=filename,
        stored_path=stored_path,
        content_type=f.mimetype,
        size_bytes=os.path.getsize(stored_path),
        uploaded_by=user_id
    )
    db.session.add(attachment)
    db.session.commit()
    _record_audit(user_id, "case_attachment_added", {"case_id": case.id, "filename": filename})
    _record_case_event(case.id, user_id, "attachment_added", {"filename": filename})
    return redirect(url_for('case_detail', case_id=case.id))

@app.route("/cases/attachment/<int:attachment_id>")
def download_case_attachment(attachment_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    attachment = CaseAttachment.query.get(attachment_id)
    if not attachment:
        return redirect(url_for('dashboard'))
    case = Case.query.get(attachment.case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    directory = os.path.dirname(attachment.stored_path)
    return send_from_directory(directory, os.path.basename(attachment.stored_path), as_attachment=True, download_name=attachment.filename)

@app.route("/cases/<int:case_id>/checklist", methods=["POST"])
def update_case_checklist(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    item_id = request.form.get("item_id")
    status = (request.form.get("status") or "open").strip().lower()
    item = CaseChecklistItem.query.filter_by(id=item_id, case_id=case_id).first()
    if item and status in ("open", "done"):
        item.status = status
        db.session.add(item)
        db.session.commit()
        _record_case_event(case.id, user_id, "checklist_updated", {"item": item.item, "status": status, "framework": item.framework})
    return redirect(url_for('case_detail', case_id=case.id))

@app.route("/cases/<int:case_id>/postmortem")
def case_postmortem(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    events = CaseEvent.query.filter_by(case_id=case_id).order_by(CaseEvent.created_at.asc()).all()
    notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at.asc()).all()
    sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
    lessons = []
    if sim:
        missed = [e.get("stage") for e in (sim.events or []) if e.get("status") == "Missed"]
        if missed:
            lessons.append(f"Improve detection at stages: {', '.join(sorted(set(missed)))}.")
    if not lessons:
        lessons.append("Review alerting thresholds and improve visibility where needed.")
    return render_template("postmortem.html", case=case, events=events, notes=notes, lessons=lessons)

@app.route("/reports/weekly")
def weekly_report():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    data = _weekly_report_data(days=7)
    return render_template("weekly_report.html", report=data)


@app.route("/cases/<int:case_id>/playbook/run", methods=["POST"])
def run_case_playbook(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
    attack_type = (sim.attack_type if sim else request.form.get("attack_type")) or ""
    playbook = incident_playbooks.get(attack_type)
    if not playbook:
        flash("No playbook available for this case.", "error")
        return redirect(url_for('case_detail', case_id=case.id))
    steps = playbook.get("blue_team", [])
    for step in steps:
        db.session.add(CaseNote(case_id=case.id, author_id=user_id, note=f"[Playbook] {step}"))
    db.session.commit()
    _record_audit(user_id, "playbook_run", {"case_id": case.id, "attack_type": attack_type})
    _record_case_event(case.id, user_id, "playbook_run", {"attack_type": attack_type, "steps": len(steps)})
    return redirect(url_for('case_detail', case_id=case.id))


def _apply_retention():
    policy = RetentionPolicy.query.first()
    if not policy or not policy.enabled:
        return
    now = datetime.utcnow()
    try:
        if policy.simulations_days and policy.simulations_days > 0:
            cutoff = now - timedelta(days=policy.simulations_days)
            Simulation.query.filter(Simulation.created_at < cutoff).delete()
        if policy.audit_days and policy.audit_days > 0:
            cutoff = now - timedelta(days=policy.audit_days)
            AuditLog.query.filter(AuditLog.created_at < cutoff).delete()
        if getattr(policy, "live_logs_days", None) and policy.live_logs_days > 0:
            cutoff = now - timedelta(days=policy.live_logs_days)
            LiveLog.query.filter(LiveLog.created_at < cutoff).delete()
        db.session.commit()
    except Exception as e:
        print(f"Retention purge failed: {e}")
        db.session.rollback()


@app.route("/admin/retention", methods=["POST"])
@_require_roles("admin")
def update_retention():
    sims = (request.form.get("simulations_days") or "").strip()
    audits = (request.form.get("audit_days") or "").strip()
    live_logs = (request.form.get("live_logs_days") or "").strip()
    enabled = request.form.get("enabled") == "on"
    policy = RetentionPolicy.query.first()
    if not policy:
        policy = RetentionPolicy()
    policy.simulations_days = int(sims) if sims.isdigit() else policy.simulations_days
    policy.audit_days = int(audits) if audits.isdigit() else policy.audit_days
    policy.live_logs_days = int(live_logs) if live_logs.isdigit() else (policy.live_logs_days or 30)
    policy.enabled = enabled
    db.session.add(policy)
    db.session.commit()
    _apply_retention()
    _record_audit(session.get("user_id"), "retention_updated", {"simulations_days": policy.simulations_days, "audit_days": policy.audit_days, "live_logs_days": policy.live_logs_days, "enabled": policy.enabled})
    return redirect(url_for('admin_users'))


def _background_retention_job():
    with app.app_context():
        _apply_retention()


def _background_schedule_job():
    with app.app_context():
        _run_due_schedules_background()


def _background_threat_summary_job():
    with app.app_context():
        try:
            discoveries = ThreatDiscovery.query.order_by(ThreatDiscovery.created_at.desc()).limit(20).all()
            if not discoveries:
                return
            data = [{"source": d.source, "sample": d.sample} for d in discoveries]
            if AI_ENABLED:
                summary = ai_advisor.generate_threat_summary(data)
            else:
                summary = _build_threat_summary(discoveries)
            db.session.add(ThreatSummary(summary=summary))
            db.session.commit()
        except Exception as e:
            print(f"Threat summary job failed: {e}")
            db.session.rollback()

def _check_case_sla():
    now = datetime.utcnow()
    cases = Case.query.filter(Case.status.in_(["Open", "Investigating"]), Case.escalated == False).all()
    for c in cases:
        last = c.updated_at or c.created_at
        if not last:
            continue
        age_hours = (now - last).total_seconds() / 3600.0
        if c.sla_hours and age_hours > c.sla_hours:
            c.status = "Escalated"
            c.escalated = True
            db.session.add(c)
    db.session.commit()


@app.route("/admin/users", methods=["GET", "POST"])
@_require_roles("admin")
def admin_users():
    if request.method == "POST":
        user_id = int(request.form.get("user_id", 0))
        role = request.form.get("role")
        if role not in ("admin", "analyst", "viewer"):
            return redirect(url_for('admin_users'))
        user = User.query.get(user_id)
        if user:
            user.role = role
            db.session.add(user)
            db.session.commit()
            _record_audit(session.get("user_id"), "role_updated", {"target_user_id": user_id, "role": role})
        return redirect(url_for('admin_users'))

    users = User.query.order_by(User.created_at.desc()).all()
    policy = RetentionPolicy.query.first()
    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    return render_template("admin_users.html", users=users, policy=policy, audit_logs=audit_logs)


@app.route("/upgrade", methods=["POST"])
def upgrade():
    item = request.form.get("item")
    if item in UPGRADES:
        cost = UPGRADES[item]["cost"]
        if session['budget'] >= cost:
            session['budget'] -= cost
            u = session['upgrades']
            u[UPGRADES[item]["stage"]] += UPGRADES[item]["boost"]
            session['upgrades'] = u

            # Track purchased upgrades
            purchased = session.get('upgrades_purchased', {})
            purchased[item] = purchased.get(item, 0) + 1
            session['upgrades_purchased'] = purchased

            session.modified = True
    return redirect(url_for('dashboard'))

@app.route("/simulate", methods=["POST"])
def simulate():
    attack_type = request.form.get("attack")
    variant = request.form.get("variant", "standard")
    events, score, weakest, recs = _run_simulation_for_user(attack_type, session.get("user_id"), variant=variant)

    # Save to session for the download report route
    session['last_result'] = {
        'attack': attack_type,
        'score': score,
        'events': events,
        'recs': recs
    }

    user_id = session.get('user_id')
    if user_id:
        try:
            last_sim = Simulation.query.filter_by(user_id=user_id).order_by(Simulation.created_at.desc()).first()
            if last_sim:
                session['last_sim_id'] = last_sim.id
            update_analytics_report(user_id)
        except Exception as e:
            print(f"Error updating analytics: {e}")

    analytics = calculate_analytics(session.get('user_id'))
    roi_data = calculate_upgrade_roi()
    try:
        user = User.query.get(user_id) if user_id else None
    except Exception:
        user = None

    return render_template(
        "dashboard.html",
        budget=session['budget'],
        upgrades=session['upgrades'],
        available_upgrades=UPGRADES,
        history=session['history'],
        events=events,
        score=score,
        weakest=weakest,
        recommendations=recs,
        attack_type=attack_type,
        analytics=analytics,
        roi_data=roi_data,
        incident_playbooks=incident_playbooks,
        playbook=incident_playbooks.get(attack_type),
        user=user,
        ai_enabled=AI_ENABLED,
        last_sim_id=session.get('last_sim_id'),
        saved_searches=SavedSearch.query.filter_by(user_id=user_id).order_by(SavedSearch.created_at.desc()).all(),
        presets=SimulationPreset.query.filter_by(user_id=user_id).order_by(SimulationPreset.created_at.desc()).all(),
        schedules=SimulationSchedule.query.filter_by(user_id=user_id).order_by(SimulationSchedule.created_at.desc()).all(),
        preset_lookup={p.id: p for p in SimulationPreset.query.filter_by(user_id=user_id).all()} if user_id else {},
        timeline_days=30,
        cases=Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(10).all(),
        users=User.query.order_by(User.username.asc()).all(),
        widgets=_get_widget_prefs(user_id)
    )

@app.route('/view_report')
def view_report():
    """Show last session report as a poster-style page (session-based for guests)."""
    report_data = session.get('last_result', {})
    last_sim_id = session.get('last_sim_id')
    if last_sim_id:
        # If we have a saved simulation id, redirect to the canonical report route
        return redirect(url_for('report', sim_id=last_sim_id))

    if not report_data:
        return "No report available. Please run a simulation first.", 400

    if report_data:
        report_data['severity'] = _severity_from_score(report_data.get('score', 0))
    return render_template('report_poster.html', report=report_data, ai_enabled=AI_ENABLED)


@app.route('/report/<int:sim_id>')
def report(sim_id):
    """Render a poster-style report for a saved simulation."""
    try:
        sim = Simulation.query.get_or_404(sim_id)
    except Exception:
        return "Report not found", 404

    report = {
        'attack': sim.attack_type,
        'score': sim.detection_score,
        'events': sim.events,
        'recs': sim.ai_recommendations or [],
        'threat_narrative': sim.threat_narrative,
        'severity': _severity_from_score(sim.detection_score)
    }

    return render_template('report_poster.html', report=report, sim=sim, ai_enabled=AI_ENABLED)


@app.route("/reset")
def reset():
    session.clear()
    return redirect(url_for('dashboard'))



@app.route("/analytics")
def analytics_api():
    """API endpoint for analytics data"""
    user_id = session.get('user_id')
    data = calculate_analytics(user_id)
    roi = calculate_upgrade_roi()
    return jsonify({'analytics': data, 'roi': roi})

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration"""
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if not username or not email or not password:
            flash("All fields are required", "error")
            return redirect(url_for('register'))

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return redirect(url_for('register'))

        try:
            # Create new user (in production, use proper password hashing)
            user = User(
                username=username,
                email=email,
                password_hash=password,  # Use proper hashing in production!
                budget=int(os.getenv('INITIAL_BUDGET', 5000))
            )
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            session['budget'] = user.budget
            flash(f"Welcome {username}!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"Registration error: {str(e)}", "error")
            return redirect(url_for('register'))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.password_hash == password:  # Use proper verification in production!
            session['user_id'] = user.id
            session['budget'] = user.budget
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    """User logout"""
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

@app.route("/user/profile")
def user_profile():
    """User profile and statistics"""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    try:
        user = User.query.get(user_id)
        report = AnalyticsReport.query.filter_by(user_id=user_id).first()
        recent_sims = Simulation.query.filter_by(user_id=user_id).order_by(
            Simulation.created_at.desc()
        ).limit(10).all()

        return render_template(
            "profile.html",
            user=user,
            analytics=report,
            recent_simulations=recent_sims,
            ai_enabled=AI_ENABLED
        )
    except Exception as e:
        flash(f"Error loading profile: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/insights/<panel>')
def insights_panel(panel):
    """Render a single focused insights page for: timeline, breakdown, workflow, funnel"""
    user_id = session.get('user_id')
    analytics = calculate_analytics(user_id)
    valid = {'timeline', 'breakdown', 'workflow', 'funnel'}
    if panel not in valid:
        return redirect(url_for('dashboard'))

    return render_template('insights_panel.html', panel=panel, analytics=analytics, ai_enabled=AI_ENABLED)

@app.route('/analytics-panels')
def analytics_panels_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    timeline_days = int(request.args.get('timeline_days', 30))
    selected_ioc_type = (request.args.get('ioc_type') or 'all').strip().lower()
    selected_attack_type = (request.args.get('attack_type') or 'all').strip()
    try:
        selected_top_links = int(request.args.get('top_links', 45))
    except Exception:
        selected_top_links = 45
    selected_top_links = max(10, min(100, selected_top_links))

    history = _build_history(user_id)
    analytics = calculate_analytics(user_id, history_override=history, timeline_days=timeline_days)
    ioc_types = sorted([
        (row[0] or "").lower()
        for row in db.session.query(Indicator.indicator_type).distinct().all()
        if row and row[0]
    ])
    attack_types = sorted(list(MITRE_ATTACK_MAPPING.keys()))

    analytics['ioc_technique_network'] = _ioc_technique_cooccurrence(
        user_id=user_id,
        ioc_type=None if selected_ioc_type == 'all' else selected_ioc_type,
        attack_type=None if selected_attack_type == 'all' else selected_attack_type,
        max_links=selected_top_links
    )

    try:
        user = User.query.get(user_id)
    except Exception:
        user = None

    return render_template(
        'analytics_panels.html',
        analytics=analytics,
        history=history,
        user=user,
        ai_enabled=AI_ENABLED,
        timeline_days=timeline_days,
        ioc_types=ioc_types,
        attack_types=attack_types,
        selected_ioc_type=selected_ioc_type,
        selected_attack_type=selected_attack_type,
        selected_top_links=selected_top_links
    )

@app.route('/eps-dashboard')
@_require_roles("admin", "analyst")
def eps_dashboard_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    history = _build_history(user_id)
    analytics = calculate_analytics(user_id, history_override=history, timeline_days=30) or {}
    eps = analytics.get("resource_monitor") or _resource_monitoring(history, user_id=user_id)

    try:
        user = User.query.get(user_id)
    except Exception:
        user = None

    return render_template(
        'eps_dashboard.html',
        user=user,
        eps=eps
    )

@app.route('/kpi-dashboard')
@_require_roles("admin", "analyst")
def kpi_dashboard_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    history = _build_history(user_id)
    rows = _kpi_dashboard_rows(history)
    totals = {
        "rows": len(rows),
        "alarm": sum(r["alarm"] for r in rows),
        "correlation": sum(r["correlation"] for r in rows),
        "incidents": sum(r["inc_alarm"] for r in rows)
    }
    try:
        user = User.query.get(user_id)
    except Exception:
        user = None

    return render_template(
        'kpi_dashboard.html',
        user=user,
        kpi_rows=rows,
        totals=totals
    )

@app.route('/live')
@_require_roles("admin", "analyst")
def live_dashboard():
    """Live dashboard for real-time log monitoring"""
    return render_template('live_dashboard.html', ai_enabled=AI_ENABLED)

@app.route('/live/history')
@_require_roles("admin", "analyst")
def live_history_view():
    user_id = session.get("user_id")
    try:
        limit = int(request.args.get("limit", 200))
    except Exception:
        limit = 200
    limit = max(20, min(limit, 500))

    minutes = request.args.get("minutes")
    attack_filter = (request.args.get("attack") or "").strip().lower()
    status_filter = (request.args.get("status") or "").strip().lower()
    severity_filter = (request.args.get("severity") or "").strip().lower()

    rows = []
    error = None
    try:
        query = LiveLog.query
        if user_id:
            query = query.filter(or_(LiveLog.user_id == user_id, LiveLog.user_id.is_(None)))
        else:
            query = query.filter(LiveLog.user_id.is_(None))
        if minutes:
            try:
                m = int(minutes)
                if m > 0:
                    cutoff = datetime.utcnow() - timedelta(minutes=m)
                    query = query.filter(LiveLog.created_at >= cutoff)
            except Exception:
                pass

        db_rows = query.order_by(LiveLog.created_at.desc()).limit(limit).all()
        for row in db_rows:
            raw = row.raw_log or {}
            payload = row.payload if isinstance(row.payload, dict) else {}
            event = payload.get("event") or row.mapped_event or {}

            attack = str(payload.get("attack") or raw.get("attack_type") or "Unknown")
            stage = str(event.get("stage") or raw.get("kill_chain_stage") or "")
            status = str(event.get("status") or ("Detected" if raw.get("detected") else "Missed"))
            severity = str(payload.get("severity") or event.get("severity") or raw.get("severity") or "").lower()
            description = str(raw.get("description") or event.get("reason") or "")

            if attack_filter and attack_filter != attack.lower():
                continue
            if status_filter and status_filter != status.lower():
                continue
            if severity_filter and severity_filter != severity:
                continue

            rows.append({
                "created_at": row.created_at,
                "attack": attack,
                "stage": stage,
                "status": status,
                "severity": severity,
                "tool": raw.get("tool") or raw.get("log_type") or "",
                "event_id": event.get("event_id") or "",
                "description": description,
                "raw": raw
            })
    except Exception as e:
        error = str(e)
        rows = []

    return render_template(
        "live_history.html",
        rows=rows,
        error=error,
        limit=limit,
        minutes=minutes or "",
        attack=attack_filter,
        status=status_filter,
        severity=severity_filter
    )

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

def _process_live_log(log, emit_socket=True, save_sim_db=True):
    """Process a live log payload and return (payload, event, score, weakest, recs)."""
    if not log.get("kill_chain_stage"):
        log["kill_chain_stage"] = _infer_stage(log)
    attack_type = log.get("attack_type")
    severity = _normalize_severity(log.get("severity") or ATTACK_SEVERITY.get(attack_type))
    log["severity"] = severity

    # Threat intel enrichment (IOCs)
    iocs = _extract_iocs(log)
    for ioc in iocs:
        try:
            _record_indicator(
                ioc.get("type"),
                ioc.get("value"),
                source="log",
                attack_type=log.get("attack_type"),
                stage=log.get("kill_chain_stage"),
                confidence=0.6
            )
        except Exception as e:
            print(f"Indicator record failed: {e}")

    # Map to kill chain event
    event = map_log_to_event(log)
    event_id = str(uuid.uuid4())
    event["event_id"] = event_id
    event["severity"] = severity
    _index_live_log(log, event)
    _record_threat_discovery("log", {
        "attack_type": log.get("attack_type"),
        "kill_chain_stage": log.get("kill_chain_stage"),
        "tool": log.get("tool"),
        "detected": log.get("detected"),
        "description": log.get("description"),
        "miss_reason": log.get("miss_reason")
    })

    # Build a mini simulation result
    detected = 1 if event["status"] == "Detected" else 0
    score = int((detected / 1) * 100)

    weakest = [event["stage"]] if event["status"] == "Missed" else []
    recs = _recommendations_for_event(event)

    chain_events = _expand_chain_event(event)
    aggregate_chain = _aggregate_live_chain(attack_type)

    # Save into session history (SOC-style)
    history = session.get("history", [])
    history.insert(0, {
        "attack": log.get("attack_type"),
        "score": score,
        "time": datetime.utcnow().strftime("%H:%M"),
        "events": chain_events,
        "weakest": weakest,
        "source": "live"
    })
    session["history"] = history
    session.modified = True

    payload = {
        'attack': attack_type,
        'score': score,
        'event': event,
        'chain_events': chain_events,
        'aggregate_chain': aggregate_chain,
        'recommendations': recs,
        'timestamp': datetime.utcnow().strftime("%H:%M:%S"),
        'severity': severity,
        'iocs': iocs,
        'ts': datetime.utcnow().isoformat(),
        'source': 'live'
    }
    payload["analysis"] = _build_live_analysis(event, chain_events, aggregate_chain, recs, iocs)
    LIVE_EVENTS.appendleft(payload)

    alerts = []
    user_id = session.get("user_id")
    try:
        rules = AlertRule.query.filter_by(enabled=True).all()
        for rule in rules:
            if rule.user_id and rule.user_id != user_id:
                continue
            if _match_alert_rule(rule, payload):
                alerts.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "message": f"{rule.name}: {payload.get('attack')} at {event.get('stage')}"
                })
                if rule.auto_case and user_id:
                    _create_case_from_event(user_id, payload, title_prefix=f"Rule {rule.name}")
    except Exception as e:
        print(f"Alert rule evaluation failed: {e}")

    if emit_socket:
        socketio.emit('new_log', payload)
        if alerts:
            socketio.emit('alert', {"alerts": alerts})

    # OPTIONAL: Save to DB if user logged in
    if save_sim_db and session.get("user_id"):
        sim = Simulation(
            user_id=session["user_id"],
            attack_type=log.get("attack_type"),
            detection_score=score,
            events=[event],
            weakest_stages=weakest,
            variant="live",
            tags=["live_log"]
        )
        db.session.add(sim)
        db.session.commit()
        try:
            update_analytics_report(session["user_id"], skip_ai=True)
        except Exception as e:
            print(f"Analytics report update failed (live): {e}")
    if save_sim_db:
        try:
            db.session.add(LiveLog(
                user_id=session.get("user_id"),
                raw_log=log,
                mapped_event=event,
                payload=payload
            ))
            db.session.commit()
        except Exception as e:
            print(f"Live log persistence failed: {e}")
            db.session.rollback()

    return payload, event, score, weakest, recs

@app.route("/api/logs", methods=["POST"])
def receive_logs():
    log = request.get_json()
    if not log:
        return jsonify({"error": "Invalid log"}), 400
    required = ["attack_type", "tool", "detected", "description"]
    for key in required:
        if key not in log or log.get(key) in (None, ""):
            return jsonify({"error": f"Missing field: {key}"}), 400
    if not isinstance(log.get("detected"), (bool, int)):
        return jsonify({"error": "Field 'detected' must be boolean"}), 400

    # Store raw log
    received_logs.append(log)
    _, event, score, _, recs = _process_live_log(log, emit_socket=True, save_sim_db=True)

    return jsonify({
        "status": "log processed",
        "mapped_event": event,
        "recommendations": recs
    }), 200

@app.route("/api/live/replay")
def live_replay():
    limit = request.args.get("limit", 50)
    minutes = request.args.get("minutes")
    try:
        limit = int(limit)
    except Exception:
        limit = 50
    limit = max(1, min(limit, 200))
    events = []
    try:
        query = LiveLog.query
        if session.get("user_id"):
            query = query.filter(or_(LiveLog.user_id == session.get("user_id"), LiveLog.user_id.is_(None)))
        else:
            query = query.filter(LiveLog.user_id.is_(None))
        if minutes:
            m = int(minutes)
            cutoff = datetime.utcnow() - timedelta(minutes=m)
            query = query.filter(LiveLog.created_at >= cutoff)
        rows = query.order_by(LiveLog.created_at.desc()).limit(limit).all()
        for r in rows:
            if isinstance(r.payload, dict):
                payload = dict(r.payload)
                event = payload.get("event") or r.mapped_event or {}
                chain_events = payload.get("chain_events") or (_expand_chain_event(event) if event else [])
                aggregate_chain = payload.get("aggregate_chain") or chain_events
                recs = payload.get("recommendations") or _recommendations_for_event(event)
                iocs = payload.get("iocs") or _extract_iocs(r.raw_log or {})

                payload.setdefault("chain_events", chain_events)
                payload.setdefault("aggregate_chain", aggregate_chain)
                payload.setdefault("recommendations", recs)
                payload.setdefault("iocs", iocs)
                if not payload.get("analysis"):
                    payload["analysis"] = _build_live_analysis(event, chain_events, aggregate_chain, recs, iocs)
                events.append(payload)
            else:
                event = r.mapped_event or {}
                chain_events = _expand_chain_event(event) if event else []
                recs = _recommendations_for_event(event)
                iocs = _extract_iocs(r.raw_log or {})
                payload = {
                    "attack": (r.raw_log or {}).get("attack_type"),
                    "event": event,
                    "timestamp": r.created_at.strftime("%H:%M:%S") if r.created_at else "",
                    "ts": r.created_at.isoformat() if r.created_at else None,
                    "source": "live",
                    "chain_events": chain_events,
                    "aggregate_chain": chain_events,
                    "recommendations": recs,
                    "iocs": iocs
                }
                payload["analysis"] = _build_live_analysis(event, chain_events, chain_events, recs, iocs)
                events.append(payload)
    except Exception as e:
        print(f"Live replay DB load failed: {e}")
        events = list(LIVE_EVENTS)
        if minutes:
            try:
                m = int(minutes)
                cutoff = datetime.utcnow() - timedelta(minutes=m)
                filtered = []
                for ev in events:
                    ts = ev.get("ts")
                    if not ts:
                        continue
                    try:
                        if datetime.fromisoformat(ts) >= cutoff:
                            filtered.append(ev)
                    except Exception:
                        continue
                events = filtered
            except Exception:
                pass
    return jsonify({"events": events[:limit]})

@app.route("/api/live/correlations")
def live_correlations():
    groups = {}
    for ev in list(LIVE_EVENTS):
        for ioc in ev.get("iocs") or []:
            key = f"{ioc.get('type')}:{ioc.get('value')}"
            entry = groups.setdefault(key, {
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "count": 0,
                "attacks": set(),
                "stages": set()
            })
            entry["count"] += 1
            entry["attacks"].add(ev.get("attack"))
            entry["stages"].add((ev.get("event") or {}).get("stage"))
    items = []
    for g in groups.values():
        items.append({
            "type": g["type"],
            "value": g["value"],
            "count": g["count"],
            "attacks": sorted([a for a in g["attacks"] if a]),
            "stages": sorted([s for s in g["stages"] if s])
        })
    items.sort(key=lambda x: x["count"], reverse=True)
    return jsonify({"correlations": items[:50]})

@app.route("/api/live/filters", methods=["GET", "POST", "DELETE"])
def live_filters():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    if request.method == "GET":
        rows = LiveFilter.query.filter_by(user_id=user_id).order_by(LiveFilter.created_at.desc()).all()
        return jsonify({"filters": [{"id": r.id, "name": r.name, "filters": r.filters} for r in rows]})
    if request.method == "POST":
        payload = request.get_json() or {}
        name = (payload.get("name") or "").strip()
        filters = payload.get("filters") or {}
        if not name:
            return jsonify({"error": "Name is required"}), 400
        row = LiveFilter(user_id=user_id, name=name, filters=filters)
        db.session.add(row)
        db.session.commit()
        try:
            socketio.emit('live_filters_updated', {"action": "saved", "id": row.id})
        except Exception:
            pass
        return jsonify({"status": "saved", "id": row.id})
    if request.method == "DELETE":
        payload = request.get_json() or {}
        fid = payload.get("id")
        if not fid:
            return jsonify({"error": "id required"}), 400
        row = LiveFilter.query.filter_by(id=fid, user_id=user_id).first()
        if row:
            db.session.delete(row)
            db.session.commit()
            try:
                socketio.emit('live_filters_updated', {"action": "deleted", "id": fid})
            except Exception:
                pass
        return jsonify({"status": "deleted"})

@app.route("/cases/create_from_event", methods=["POST"])
def create_case_from_event():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    payload = request.get_json() or {}
    case = _create_case_from_event(user_id, payload)
    _record_audit(user_id, "case_created_live", {"case_id": case.id})
    return jsonify({"status": "created", "case_id": case.id})

@app.route("/cases/export/<int:case_id>")
def export_case(case_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    case = Case.query.get(case_id)
    if not case or case.user_id != user_id:
        return redirect(url_for('dashboard'))
    notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at.asc()).all()
    attachments = CaseAttachment.query.filter_by(case_id=case_id).order_by(CaseAttachment.created_at.asc()).all()
    sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
    data = {
        "case": {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "severity": case.severity,
            "sla_hours": case.sla_hours,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None
        },
        "notes": [{"created_at": n.created_at.isoformat(), "note": n.note} for n in notes],
        "attachments": [
            {"filename": a.filename, "content_type": a.content_type, "size_bytes": a.size_bytes, "created_at": a.created_at.isoformat()}
            for a in attachments
        ],
        "simulation": {
            "id": sim.id,
            "attack_type": sim.attack_type,
            "detection_score": sim.detection_score,
            "events": sim.events,
            "weakest_stages": sim.weakest_stages
        } if sim else None
    }
    resp = Response(json.dumps(data, indent=2), mimetype="application/json")
    resp.headers["Content-Disposition"] = f"attachment; filename=case_{case_id}.json"
    return resp


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        _ensure_schema()
        if RetentionPolicy.query.count() == 0:
            db.session.add(RetentionPolicy())
            db.session.commit()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
