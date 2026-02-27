"""Simulation execution helpers for kill-chain scenarios."""
import random
from datetime import datetime
from flask import session

from config_data import attack_profiles, kill_chain_data, recommendations_map

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
