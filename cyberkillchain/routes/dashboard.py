from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify, flash
from datetime import datetime
import os
from models import db, Simulation, User
from utils.helpers import (
    get_simulation, _build_history, calculate_analytics, calculate_upgrade_roi,
    update_analytics_report, incident_playbooks, UPGRADES, kill_chain_data
)
from ai_advisor import ai_advisor, AI_ENABLED

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route("/")
def dashboard():
    user_id = session.get('user_id')

    # Redirect to login if not authenticated
    if not user_id:
        return redirect(url_for('auth.login'))

    # Support dashboard filtering via ?filter_stage=analyzed|found|created
    filter_stage = request.args.get('filter_stage')
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

    analytics = calculate_analytics(user_id, history_override=filtered_history)
    roi_data = calculate_upgrade_roi()

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
                           filter_stage=filter_stage)

@dashboard_bp.route('/ai/insights', methods=['POST'])
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

@dashboard_bp.route("/upgrade", methods=["POST"])
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
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route("/simulate", methods=["POST"])
def simulate():
    attack_type = request.form.get("attack")
    events, score, weakest, recs = get_simulation(attack_type)

    # Update History
    h = session['history']
    h.insert(0, {"attack": attack_type, "score": score, "time": datetime.now().strftime("%H:%M")})
    session['history'] = h

    # Save to session for the download report route
    session['last_result'] = {
        'attack': attack_type,
        'score': score,
        'events': events,
        'recs': recs
    }

    # Save to database if user is logged in
    user_id = session.get('user_id')
    if user_id:
        try:
            # Create simulation record
            simulation = Simulation(
                user_id=user_id,
                attack_type=attack_type,
                detection_score=score,
                events=events,
                weakest_stages=weakest
            )

            # Generate AI insights if enabled
            if AI_ENABLED:
                try:
                    threat_narrative = ai_advisor.generate_threat_narrative(attack_type, score, events)
                    simulation.threat_narrative = threat_narrative

                    ai_recs = ai_advisor.generate_intelligent_recommendations(
                        attack_type, score, weakest, session.get('upgrades', {})
                    )
                    simulation.ai_recommendations = ai_recs
                except Exception as e:
                    print(f"Error generating AI insights: {e}")

            db.session.add(simulation)
            db.session.commit()
            # Save last simulation id in session so we can view the poster later
            session['last_sim_id'] = simulation.id

            # Update analytics report
            update_analytics_report(user_id)
        except Exception as e:
            print(f"Error saving simulation: {e}")
            db.session.rollback()

    session.modified = True

    analytics = calculate_analytics(session.get('user_id'))
    roi_data = calculate_upgrade_roi()

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
        ai_enabled=AI_ENABLED,
        last_sim_id=session.get('last_sim_id')
    )

@dashboard_bp.route("/reset")
def reset():
    session.clear()
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/insights/<panel>')
def insights_panel(panel):
    """Render a single focused insights page for: timeline, breakdown, workflow, funnel"""
    user_id = session.get('user_id')
    analytics = calculate_analytics(user_id)
    valid = {'timeline', 'breakdown', 'workflow', 'funnel'}
    if panel not in valid:
        return redirect(url_for('dashboard.dashboard'))

    return render_template('insights_panel.html', panel=panel, analytics=analytics, ai_enabled=AI_ENABLED)
