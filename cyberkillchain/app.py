from flask import session, redirect, url_for, flash
from datetime import datetime, timedelta
import os
from collections import deque
from functools import wraps
from sqlalchemy import or_
from models import db, User, Simulation, UpgradePurchase, AnalyticsReport, SavedSearch, SimulationPreset, SimulationSchedule, Case, CaseNote, CaseAttachment, CaseEvent, CaseChecklistItem, AuditLog, RetentionPolicy, ThreatSignature, ThreatDiscovery, ThreatSummary, ThreatAdvisory, ThreatSettings, UserWidget, Indicator, IndicatorRelation, AlertRule, LiveFilter, LiveLog, FeatureModuleSetting
from factory import create_app
from dependencies import build_route_dependencies

received_logs = []
LIVE_EVENTS = deque(maxlen=200)

app, socketio, ai_advisor, AI_ENABLED = create_app()

# Optional background scheduler
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    APSCHEDULER_AVAILABLE = True
except Exception:
    APSCHEDULER_AVAILABLE = False

from config_data import (
    ATTACK_SEVERITY,
    UPGRADES,
    kill_chain_data,
    MITRE_ATTACK_MAPPING,
    recommendations_map,
    incident_playbooks,
    CASE_TEMPLATES,
    COMPLIANCE_CHECKLISTS,
)
from simulation_engine import get_simulation, get_simulation_with_upgrades
from services.es_search_service import ESSearchService
from services.case_threat_service import CaseThreatService
from services.jobs_service import JobsService
from services.analytics_service import AnalyticsService
from services.live_event_service import LiveEventService
from services.history_service import HistoryService
from services.simulation_service import SimulationService
from services.schema_migration import ensure_schema, init_migration_support
from feature_modules import (
    FEATURE_MODULES,
    module_default_settings,
    module_settings_for_user,
    feature_module_preview,
)
from route_handlers.auth_routes import register_auth_routes
from route_handlers.live_routes import register_live_routes
from route_handlers.cases_routes import register_cases_routes
from route_handlers.ops_routes import register_ops_routes
from route_handlers.core_routes import register_core_routes

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


history_service = HistoryService({
    "session": session,
    "LiveLog": LiveLog,
    "Simulation": Simulation,
    "or_": or_,
    "live_events": LIVE_EVENTS,
    "parse_event_time_fn": _parse_event_time,
    "expand_chain_event_fn": lambda event: _expand_chain_event(event),
    "merge_history_fn": _merge_history,
    "extract_event_id_fn": _extract_event_id,
    "is_live_simulation_fn": _is_live_simulation,
})

def _build_live_db_history(user_id=None, limit=500):
    return history_service.build_live_db_history(user_id=user_id, limit=limit)

def _build_history(user_id=None):
    return history_service.build_history(user_id=user_id)

analytics_service = AnalyticsService({
    "MITRE_ATTACK_MAPPING": MITRE_ATTACK_MAPPING,
    "kill_chain_data": kill_chain_data,
    "Indicator": Indicator,
    "LiveLog": LiveLog,
    "AlertRule": AlertRule,
    "or_": or_,
    "build_history_fn": lambda uid=None: _build_history(uid),
    "parse_event_time_fn": lambda ts: _parse_event_time(ts),
    "normalize_severity_fn": lambda v: _normalize_severity(v),
    "severity_rank_fn": lambda v: _severity_rank(v),
    "ATTACK_SEVERITY": ATTACK_SEVERITY,
})


def _parse_history_time(ts):
    return analytics_service.parse_history_time(ts)


def _rolling_avg(history, days=7):
    return analytics_service.rolling_avg(history, days=days)


def _prev_rolling_avg(history, days=7):
    return analytics_service.prev_rolling_avg(history, days=days)


def _case_timeline(history, days=30):
    return analytics_service.case_timeline(history, days=days)


def _case_breakdown(history):
    return analytics_service.case_breakdown(history)


def _workflow_analysis(history):
    return analytics_service.workflow_analysis(history)


def _threat_analysis_funnel(history):
    return analytics_service.threat_analysis_funnel(history)

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
    return simulation_service.run_due_schedules(user_id, _run_simulation_for_user)

def _run_due_schedules_background():
    return simulation_service.run_due_schedules_background(_run_simulation_for_user_bg)

def calculate_upgrade_roi():
    return simulation_service.calculate_upgrade_roi()

def update_analytics_report(user_id, skip_ai=False):
    return simulation_service.update_analytics_report(user_id, skip_ai=skip_ai)

live_event_service = LiveEventService({
    "kill_chain_data": kill_chain_data,
    "recommendations_map": recommendations_map,
    "incident_playbooks": incident_playbooks,
    "Case": Case,
    "Indicator": Indicator,
    "IndicatorRelation": IndicatorRelation,
    "db": db,
})

map_log_to_event = live_event_service.map_log_to_event
_infer_stage = live_event_service.infer_stage
_expand_chain_event = live_event_service.expand_chain_event
_recommendations_for_event = live_event_service.recommendations_for_event
_build_live_analysis = live_event_service.build_live_analysis
_severity_from_score = live_event_service.severity_from_score
_severity_bucket_from_label = live_event_service.severity_bucket_from_label
_normalize_severity = live_event_service.normalize_severity
_severity_rank = live_event_service.severity_rank
_build_live_brief = live_event_service.build_live_brief
_fallback_recommendation_explain = live_event_service.fallback_recommendation_explain
_fallback_next_steps = live_event_service.fallback_next_steps
_fallback_case_summary = live_event_service.fallback_case_summary
_fallback_root_cause = live_event_service.fallback_root_cause
_fallback_triage = live_event_service.fallback_triage
_create_case_from_event = live_event_service.create_case_from_event
_match_alert_rule = live_event_service.match_alert_rule
_aggregate_live_chain = lambda attack_type: live_event_service.aggregate_live_chain(LIVE_EVENTS, attack_type)
es_search_service = ESSearchService(
    received_logs=received_logs,
    build_history_fn=lambda user_id=None: _build_history(user_id),
)


def _index_simulation_events(attack_type, score, events, user_id=None):
    return es_search_service.index_simulation_events(attack_type, score, events, user_id=user_id)


def _index_live_log(log, mapped_event):
    return es_search_service.index_live_log(log, mapped_event)


def search_all(query, user_id=None, limit=25):
    return es_search_service.search_all(query, user_id=user_id, limit=limit)

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
    return analytics_service.mitre_heatmap(history)


def _mitre_coverage(history):
    return analytics_service.mitre_coverage(history)


def _ioc_technique_cooccurrence(user_id=None, ioc_type=None, attack_type=None, max_indicators=240, max_links=45):
    return analytics_service.ioc_technique_cooccurrence(
        user_id=user_id,
        ioc_type=ioc_type,
        attack_type=attack_type,
        max_indicators=max_indicators,
        max_links=max_links,
    )


def _correlation_matrix(history):
    return analytics_service.correlation_matrix(history)


def _kill_chain_gaps(history, top_n=3):
    return analytics_service.kill_chain_gaps(history, top_n=top_n)


def _source_compare(history):
    return analytics_service.source_compare(history)


def _resource_monitoring(history, user_id=None):
    return analytics_service.resource_monitoring(history, user_id=user_id)


def _kpi_dashboard_rows(history):
    return analytics_service.kpi_dashboard_rows(history)


def _compute_rule_effectiveness(user_id, lookback_days=30, trend_days=14):
    return analytics_service.compute_rule_effectiveness(user_id, lookback_days=lookback_days, trend_days=trend_days)

def _run_simulation_for_user(attack_type, user_id, source="manual", variant="standard"):
    return simulation_service.run_simulation_for_user(attack_type, user_id, source=source, variant=variant)

def _run_simulation_for_user_bg(attack_type, user_id):
    return simulation_service.run_simulation_for_user_bg(attack_type, user_id)

case_threat_service = CaseThreatService({
    "db": db,
    "session": session,
    "Case": Case,
    "CaseNote": CaseNote,
    "CaseEvent": CaseEvent,
    "CaseChecklistItem": CaseChecklistItem,
    "AuditLog": AuditLog,
    "UserWidget": UserWidget,
    "ThreatSignature": ThreatSignature,
    "ThreatDiscovery": ThreatDiscovery,
    "ThreatSettings": ThreatSettings,
    "Indicator": Indicator,
    "recommendations_map": recommendations_map,
    "compliance_checklists": COMPLIANCE_CHECKLISTS,
    "build_history_fn": lambda uid=None: _build_history(uid),
    "calculate_analytics_fn": lambda uid=None: calculate_analytics(uid),
    "parse_event_time_fn": _parse_event_time,
})


def _record_audit(actor_id, action, meta=None):
    return case_threat_service.record_audit(actor_id, action, meta)


def _record_case_event(case_id, actor_id, action, meta=None):
    return case_threat_service.record_case_event(case_id, actor_id, action, meta)


live_event_service.record_case_event_fn = _record_case_event


def _ensure_case_checklist(case_id):
    return case_threat_service.ensure_case_checklist(case_id)


def _weekly_report_data(days=7):
    return case_threat_service.weekly_report_data(days)


def _get_widget_prefs(user_id):
    return case_threat_service.get_widget_prefs(user_id)


def _threat_fingerprint(payload):
    return case_threat_service.threat_fingerprint(payload)


def _record_threat_discovery(source, payload):
    return case_threat_service.record_threat_discovery(source, payload)


simulation_service = SimulationService({
    "db": db,
    "session": session,
    "Simulation": Simulation,
    "SimulationSchedule": SimulationSchedule,
    "SimulationPreset": SimulationPreset,
    "UpgradePurchase": UpgradePurchase,
    "AnalyticsReport": AnalyticsReport,
    "UPGRADES": UPGRADES,
    "AI_ENABLED": AI_ENABLED,
    "ai_advisor": ai_advisor,
    "get_simulation_fn": get_simulation,
    "get_simulation_with_upgrades_fn": get_simulation_with_upgrades,
    "index_simulation_events_fn": lambda attack_type, score, events, user_id=None: _index_simulation_events(attack_type, score, events, user_id=user_id),
    "record_threat_discovery_fn": lambda source, payload: _record_threat_discovery(source, payload),
})


def _enrich_ip(ip_value):
    return case_threat_service.enrich_ip(ip_value)


def _extract_iocs(log):
    return case_threat_service.extract_iocs(log)


def _default_expiry(indicator_type):
    return case_threat_service.default_expiry(indicator_type)


def _record_indicator(indicator_type, value, source="log", attack_type=None, stage=None, confidence=0.5):
    return case_threat_service.record_indicator(indicator_type, value, source=source, attack_type=attack_type, stage=stage, confidence=confidence)


def _build_threat_summary(discoveries):
    return case_threat_service.build_threat_summary(discoveries)


def _build_threat_advisories(discoveries, max_items=6):
    return case_threat_service.build_threat_advisories(discoveries, max_items=max_items)


def _build_advisory_trend(advisories, days=7):
    return case_threat_service.build_advisory_trend(advisories, days=days)

# --- Routes ---
register_auth_routes(app, {
    "db": db,
    "User": User,
    "Simulation": Simulation,
    "AnalyticsReport": AnalyticsReport,
    "AI_ENABLED": AI_ENABLED,
})
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

jobs_service = JobsService(app, APSCHEDULER_AVAILABLE, BackgroundScheduler if APSCHEDULER_AVAILABLE else None, {
    "db": db,
    "Case": Case,
    "ThreatDiscovery": ThreatDiscovery,
    "ThreatSummary": ThreatSummary,
    "AI_ENABLED": AI_ENABLED,
    "ai_advisor": ai_advisor,
    "build_threat_summary": _build_threat_summary,
    "apply_retention": lambda: _apply_retention(),
    "run_due_schedules_background": lambda: _run_due_schedules_background(),
})


def _background_retention_job():
    return jobs_service.background_retention_job()


def _background_schedule_job():
    return jobs_service.background_schedule_job()


def _background_threat_summary_job():
    return jobs_service.background_threat_summary_job()


def _check_case_sla():
    return jobs_service.check_case_sla()


def _start_scheduler_once():
    return jobs_service.start_scheduler_once()

_schema_checked = False
_migrate = init_migration_support(app, db)


def _ensure_schema():
    global _schema_checked
    if _schema_checked:
        return
    _schema_checked = True
    return ensure_schema(app, db)


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


route_deps = build_route_dependencies(locals())
register_live_routes(app, socketio, route_deps["live"])
register_cases_routes(app, route_deps["cases"])
register_ops_routes(app, route_deps["ops"])
register_core_routes(app, route_deps["core"])

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        _ensure_schema()
        if RetentionPolicy.query.count() == 0:
            db.session.add(RetentionPolicy())
            db.session.commit()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

