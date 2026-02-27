from datetime import datetime, timedelta


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


def module_default_settings(module_id):
    module = FEATURE_MODULES.get(module_id) or {}
    fields = module.get("settings") or []
    defaults = {}
    for field in fields:
        defaults[field["key"]] = field.get("default")
    return defaults


def module_settings_for_user(user_id, module_id, feature_setting_model):
    defaults = module_default_settings(module_id)
    row = feature_setting_model.query.filter_by(user_id=user_id, module_id=module_id).first()
    if not row or not isinstance(row.settings, dict):
        return defaults
    merged = defaults.copy()
    merged.update(row.settings)
    return merged


def feature_module_preview(user_id, module_id, settings, deps):
    build_history = deps["build_history"]
    calculate_analytics = deps["calculate_analytics"]
    compute_rule_effectiveness = deps["compute_rule_effectiveness"]
    case_model = deps["Case"]
    case_note_model = deps["CaseNote"]
    case_event_model = deps["CaseEvent"]
    simulation_model = deps["Simulation"]
    indicator_model = deps["Indicator"]
    live_events = deps["LIVE_EVENTS"]
    parse_event_time = deps["parse_event_time"]

    history = build_history(user_id)
    analytics = calculate_analytics(user_id, history_override=history, timeline_days=30)

    if module_id == "rule-tuning":
        metrics = compute_rule_effectiveness(user_id, lookback_days=30, trend_days=14)
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
                candidates.append({"rule": r["name"], "precision": r["precision"], "fp": r["fp"], "suggestion": suggestion})
        return {"type": "table", "title": "Tuning Suggestions", "rows": candidates[:8]}

    if module_id == "case-similarity":
        rows = []
        recent_cases = case_model.query.filter_by(user_id=user_id).order_by(case_model.updated_at.desc()).limit(10).all()
        for c in recent_cases:
            sim = simulation_model.query.get(c.simulation_id) if c.simulation_id else None
            attack = sim.attack_type if sim else "Unknown"
            similar = case_model.query.filter(case_model.user_id == user_id, case_model.id != c.id, case_model.simulation_id.isnot(None)).order_by(case_model.updated_at.desc()).limit(20).all()
            overlap = 0
            for s in similar:
                ssim = simulation_model.query.get(s.simulation_id) if s.simulation_id else None
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
        return {"type": "list", "title": "Priority MITRE Gaps", "items": gaps[:limit], "meta": f"Coverage: {coverage.get('coverage', 0)}%"}

    if module_id == "sla-heatmap":
        severity_filter = (settings.get("severity_filter") or "all").lower()
        only_breached = bool(settings.get("show_only_breached"))
        now = datetime.utcnow()
        rows = []
        cases = case_model.query.filter_by(user_id=user_id).order_by(case_model.updated_at.desc()).limit(200).all()
        for c in cases:
            sev = (c.severity or "low").lower()
            if severity_filter != "all" and sev != severity_filter:
                continue
            sla_deadline = (c.created_at or now) + timedelta(hours=int(c.sla_hours or settings.get("sla_hours_default", 48)))
            breached = now > sla_deadline and c.status not in ("Resolved", "Closed")
            if only_breached and not breached:
                continue
            rows.append({"case": c.title, "severity": c.severity, "status": c.status, "breached": "Yes" if breached else "No"})
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
        case = case_model.query.filter_by(user_id=user_id).order_by(case_model.updated_at.desc()).first()
        if not case:
            return {"type": "list", "title": "Timeline Preview", "items": []}
        events = case_event_model.query.filter(case_event_model.case_id == case.id, case_event_model.created_at >= cutoff).order_by(case_event_model.created_at.asc()).limit(30).all()
        notes = case_note_model.query.filter(case_note_model.case_id == case.id, case_note_model.created_at >= cutoff).order_by(case_note_model.created_at.asc()).limit(20).all()
        items = [f"{e.created_at.strftime('%Y-%m-%d %H:%M')} - {e.action}" for e in events]
        if settings.get("include_notes"):
            items.extend([f"{n.created_at.strftime('%Y-%m-%d %H:%M')} - Note: {n.note[:80]}" for n in notes])
        items.sort()
        return {"type": "list", "title": f"Timeline for {case.title}", "items": items[:20]}

    if module_id == "intel-confidence":
        min_conf = int(settings.get("min_confidence", 50) or 50) / 100.0
        indicators = indicator_model.query.order_by(indicator_model.last_seen.desc()).limit(200).all()
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
        noisy = (compute_rule_effectiveness(user_id).get("top_noisy") or [{}])[0]
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
        recent = [ev for ev in list(live_events) if parse_event_time(ev.get("ts")) and parse_event_time(ev.get("ts")) >= cutoff]
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
