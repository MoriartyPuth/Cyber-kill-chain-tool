from flask import Flask, render_template, request, session, redirect, url_for, Response, jsonify, flash
import random
from datetime import datetime, timedelta
import json
import os
from dotenv import load_dotenv
from models import db, User, Simulation, UpgradePurchase, AnalyticsReport, AIInsight
from ai_advisor import AISecurityAdvisor

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'cyber_security_simulation_secret_2026')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cyber_killchain.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

def get_simulation(attack_type):
    """Run a simulation for the given attack type"""
    events = []
    detected_count = 0
    base_prob = attack_profiles[attack_type]
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

def _build_history(user_id=None):
    """Return a normalized list of simulation records for analytics.
    Uses DB when user is logged in; otherwise falls back to session history."""
    history = []
    if user_id:
        try:
            sims = Simulation.query.filter_by(user_id=user_id).order_by(Simulation.created_at.desc()).all()
            history = [{
                'id': s.id,
                'attack': s.attack_type,
                'score': s.detection_score,
                'time': s.created_at.strftime('%Y-%m-%d %H:%M'),
                'events': s.events,
                'weakest': s.weakest_stages or []
            } for s in sims]
        except Exception as e:
            print(f"Error fetching DB history for analytics: {e}")
            history = session.get('history', [])
    else:
        # Session history has less detail; normalize fields
        raw = session.get('history', [])
        history = [{
            'id': None,
            'attack': h.get('attack'),
            'score': h.get('score'),
            'time': datetime.now().strftime('%Y-%m-%d ') + h.get('time', ''),
            'events': [],
            'weakest': []
        } for h in raw]
    return history


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


def calculate_analytics(user_id=None, history_override=None):
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
                ai_result['case_timeline'] = _case_timeline(history)
                ai_result['case_breakdown'] = _case_breakdown(history)
                ai_result['workflow'] = _workflow_analysis(history)
                ai_result['funnel'] = _threat_analysis_funnel(history)
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
    analytics['case_timeline'] = _case_timeline(history)
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

    # Attack breakdown labels/values for charts
    analytics['attack_labels'] = list(analytics['attack_breakdown'].keys())
    analytics['attack_values'] = list(analytics['attack_breakdown'].values())

    return analytics

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

def update_analytics_report(user_id):
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
            if AI_ENABLED and report.total_simulations >= 3:
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

# --- Routes ---
@app.before_request
def init_session():
    if 'budget' not in session: session['budget'] = int(os.getenv('INITIAL_BUDGET', 5000))
    if 'upgrades' not in session: session['upgrades'] = {s[0]: 0.0 for s in kill_chain_data}
    if 'upgrades_purchased' not in session: session['upgrades_purchased'] = {}
    if 'history' not in session: session['history'] = []
    if 'user_id' not in session: session['user_id'] = None

@app.before_request
def create_tables():
    """Create database tables on startup"""
    with app.app_context():
        db.create_all()

@app.route("/")
def dashboard():
    user_id = session.get('user_id')
    
    # Redirect to login if not authenticated
    if not user_id:
        return redirect(url_for('login'))

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

    content = f"CYBER KILL CHAIN SECURITY REPORT\n"
    content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    content += f"{'='*40}\n"
    content += f"Attack Type: {report_data.get('attack')}\n"
    content += f"Security Score: {report_data.get('score')}%\n"
    content += f"{'='*40}\n\n"
    
    content += "DETECTION LOGS:\n"
    for e in report_data.get('events', []):
        content += f"[{e['time']}] {e['stage']}: {e['status']}\n"
        content += f"    Tool: {e['tool']}\n"
        content += f"    Detail: {e['reason'] if e['status'] == 'Detected' else e['miss_reason']}\n\n"
    
    content += "REMEDIATION STEPS:\n"
    if not report_data.get('recs'):
        content += "All stages successfully detected. No immediate remediation required.\n"
    else:
        for r in report_data.get('recs', []):
            content += f"STAGE: {r['stage']}\n"
            content += f"  Improve: {r['improve']}\n"
            content += f"  Response: {r['response']}\n\n"

    # Legacy download endpoint: redirect to poster view
    return redirect(url_for('view_report'))


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
        'threat_narrative': sim.threat_narrative
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


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)