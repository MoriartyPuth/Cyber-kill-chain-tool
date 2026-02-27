from datetime import datetime


class LiveEventService:
    def __init__(self, deps=None):
        deps = deps or {}
        self.kill_chain_data = deps.get("kill_chain_data") or []
        self.recommendations_map = deps.get("recommendations_map") or {}
        self.incident_playbooks = deps.get("incident_playbooks") or {}
        self.Case = deps.get("Case")
        self.Indicator = deps.get("Indicator")
        self.IndicatorRelation = deps.get("IndicatorRelation")
        self.db = deps.get("db")
        self.record_case_event_fn = deps.get("record_case_event_fn")

    def map_log_to_event(self, log):
        return {
            "stage": log.get("kill_chain_stage"),
            "status": "Detected" if log.get("detected") else "Missed",
            "tool": log.get("tool"),
            "reason": log.get("description") if log.get("detected") else "Detection failed",
            "miss_reason": log.get("miss_reason") if not log.get("detected") else "-",
            "time": log.get("timestamp", datetime.utcnow().strftime("%H:%M:%S")),
            "severity": log.get("severity"),
        }

    def infer_stage(self, log):
        stage = (log.get("kill_chain_stage") or "").strip()
        if stage:
            return stage
        tool = (log.get("tool") or "").lower()
        desc = (log.get("description") or "").lower()

        for s, t, _, _ in self.kill_chain_data:
            if t and t.lower() in tool:
                return s

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

    def expand_chain_event(self, event):
        stage = event.get("stage")
        expanded = []
        for s, tool, _, _ in self.kill_chain_data:
            if s == stage:
                expanded.append(event)
            else:
                expanded.append(
                    {
                        "stage": s,
                        "status": "Not Observed",
                        "tool": tool or "-",
                        "reason": "-",
                        "miss_reason": "-",
                        "time": event.get("time"),
                    }
                )
        return expanded

    def aggregate_live_chain(self, live_events, attack_type):
        stage_map = {}
        for ev in list(live_events):
            if ev.get("attack") != attack_type:
                continue
            event = ev.get("event") or {}
            stage = event.get("stage")
            if stage and stage not in stage_map:
                stage_map[stage] = event
        aggregated = []
        for s, tool, _, _ in self.kill_chain_data:
            if s in stage_map:
                aggregated.append(stage_map[s])
            else:
                aggregated.append(
                    {
                        "stage": s,
                        "status": "Not Observed",
                        "tool": tool or "-",
                        "reason": "-",
                        "miss_reason": "-",
                        "time": None,
                    }
                )
        return aggregated

    def recommendations_for_event(self, event):
        stage = (event or {}).get("stage")
        status = (event or {}).get("status")
        if status != "Missed" or stage not in self.recommendations_map:
            return []
        rec = self.recommendations_map[stage]
        return [{"stage": stage, "improve": rec["improve"], "response": rec["response"]}]

    def build_live_analysis(self, event, chain_events, aggregate_chain, recommendations, iocs):
        snapshot = aggregate_chain if aggregate_chain else chain_events
        snapshot = snapshot or ([event] if event else [])
        total_stages = len(self.kill_chain_data) or 1

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
            "chain_snapshot": snapshot,
        }

    def severity_from_score(self, score):
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

    def severity_bucket_from_label(self, label):
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

    def normalize_severity(self, value):
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

    def severity_rank(self, value):
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get((value or "").lower(), 2)

    def build_live_brief(self, events):
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

    def fallback_recommendation_explain(self, event, recommendations):
        if not recommendations:
            return "No recommendations were generated for this event."
        stage = (event or {}).get("stage") or "this stage"
        return f"Recommendations focus on improving detection at {stage} based on recent misses."

    def fallback_next_steps(self, attack_type):
        playbook = self.incident_playbooks.get(attack_type, {}).get("blue_team") if attack_type else []
        if playbook:
            return playbook[:4]
        return [
            "Review relevant alerts and logs",
            "Isolate impacted systems if needed",
            "Collect evidence and preserve artifacts",
            "Escalate to incident response lead",
        ]

    def fallback_case_summary(self, case, notes, sim):
        lines = [
            f"Case '{case.title}' is currently {case.status} with severity {case.severity}.",
            f"Description: {case.description or 'No description provided.'}",
        ]
        if sim:
            lines.append(f"Linked simulation: {sim.attack_type} with detection score {sim.detection_score}%.")
        if notes:
            lines.append(f"Latest note: {notes[0].note}")
        lines.append("Next action: review evidence and update status.")
        return " ".join(lines)

    def fallback_root_cause(self, events):
        missed = [e.get("stage") for e in (events or []) if e.get("status") == "Missed"]
        if not missed:
            return "No missed stages detected; focus on validating detections and tuning thresholds."
        uniq = ", ".join(sorted(set([m for m in missed if m])))
        return f"Likely control gaps at stages: {uniq}. Review tooling, coverage, and detection logic for these stages."

    def fallback_triage(self, case, sim):
        sev_map = {"low": 20, "medium": 50, "high": 75, "critical": 90}
        base = sev_map.get((case.severity or "medium").lower(), 50)
        if case.status in ("Investigating", "Escalated"):
            base = min(100, base + 10)
        if sim:
            base = min(100, base + max(0, 60 - (sim.detection_score or 0)) // 2)
        label = "Low" if base < 40 else "Medium" if base < 70 else "High" if base < 90 else "Critical"
        return {"score": int(base), "label": label, "rationale": "Heuristic triage score based on severity and status."}

    def case_description_from_event(self, payload):
        event = payload.get("event") or {}
        iocs = payload.get("iocs") or []
        lines = [
            f"Attack: {payload.get('attack')}",
            f"Stage: {event.get('stage')}",
            f"Status: {event.get('status')}",
            f"Severity: {payload.get('severity')}",
            f"Tool: {event.get('tool')}",
            f"Reason: {event.get('reason')}",
        ]
        miss_reason = event.get("miss_reason")
        if miss_reason and miss_reason not in ("-", "\u2014", "Ã¢â‚¬â€"):
            lines.append(f"Miss Reason: {miss_reason}")
        if iocs:
            lines.append("IOCs:")
            for ioc in iocs[:10]:
                lines.append(f"- {ioc.get('type')}: {ioc.get('value')}")
        return "\n".join([line for line in lines if line])

    def create_case_from_event(self, user_id, payload, title_prefix="Live Alert"):
        event = payload.get("event") or {}
        title = f"{title_prefix}: {payload.get('attack')} - {event.get('stage')}"
        case = self.Case(
            user_id=user_id,
            title=title,
            description=self.case_description_from_event(payload),
            status="Investigating",
            severity=(payload.get("severity") or "Medium").title(),
        )
        self.db.session.add(case)
        self.db.session.commit()
        for ioc in payload.get("iocs") or []:
            indicator = self.Indicator.query.filter_by(indicator_type=ioc.get("type"), value=ioc.get("value")).first()
            if indicator:
                self.db.session.add(
                    self.IndicatorRelation(
                        indicator_id=indicator.id,
                        relation_type="case",
                        relation_id=str(case.id),
                        meta={"source": "live_event"},
                    )
                )
        self.db.session.commit()
        if self.record_case_event_fn:
            self.record_case_event_fn(case.id, user_id, "case_created", {"source": "live_event"})
        return case

    def match_alert_rule(self, rule, payload):
        event = payload.get("event") or {}
        if rule.attack_type and rule.attack_type != payload.get("attack"):
            return False
        if rule.stage and rule.stage != event.get("stage"):
            return False
        if rule.status and rule.status != event.get("status"):
            return False
        sev = (payload.get("severity") or "medium").lower()
        if self.severity_rank(sev) < self.severity_rank(rule.severity_threshold):
            return False
        return True
