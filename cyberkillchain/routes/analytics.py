from flask import Blueprint, render_template, session, jsonify
from models import Simulation
from utils.helpers import calculate_analytics, calculate_upgrade_roi

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route("/analytics")
def analytics_api():
    """API endpoint for analytics data"""
    user_id = session.get('user_id')
    data = calculate_analytics(user_id)
    roi = calculate_upgrade_roi()
    return jsonify({'analytics': data, 'roi': roi})

@analytics_bp.route('/view_report')
def view_report():
    """Show last session report as a poster-style page (session-based for guests)."""
    report_data = session.get('last_result', {})
    last_sim_id = session.get('last_sim_id')
    if last_sim_id:
        # If we have a saved simulation id, redirect to the canonical report route
        return redirect(url_for('analytics.report', sim_id=last_sim_id))

    if not report_data:
        return "No report available. Please run a simulation first.", 400

    from ai_advisor import AI_ENABLED
    return render_template('report_poster.html', report=report_data, ai_enabled=AI_ENABLED)

@analytics_bp.route('/report/<int:sim_id>')
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
        'threat_narrative': sim.threat_narrative
    }

    from ai_advisor import AI_ENABLED
    return render_template('report_poster.html', report=report, sim=sim, ai_enabled=AI_ENABLED)
