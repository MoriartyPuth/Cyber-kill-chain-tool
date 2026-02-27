"""Static configuration and domain mappings for Cyber Kill Chain app."""
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
