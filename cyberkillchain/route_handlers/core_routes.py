from flask import render_template, request, session, redirect, url_for, jsonify, flash

from route_handlers.ai_routes import register_ai_routes
from route_handlers.dashboard_routes import register_dashboard_routes
from route_handlers.insights_routes import register_insights_routes
from route_handlers.presets_routes import register_presets_routes


def register_core_routes(app, deps):
    register_dashboard_routes(app, deps)
    register_ai_routes(app, deps)
    register_presets_routes(app, deps)
    register_insights_routes(app, deps)

    calculate_analytics = deps["calculate_analytics"]
    calculate_upgrade_roi = deps["calculate_upgrade_roi"]
    User = deps["User"]
    UPGRADES = deps["UPGRADES"]
    incident_playbooks = deps["incident_playbooks"]
    AI_ENABLED = deps["AI_ENABLED"]
    Case = deps["Case"]
    _get_widget_prefs = deps["_get_widget_prefs"]
    module_default_settings = deps["module_default_settings"]
    module_settings_for_user = deps["module_settings_for_user"]
    FeatureModuleSetting = deps["FeatureModuleSetting"]
    feature_module_preview = deps["feature_module_preview"]
    _compute_rule_effectiveness = deps["_compute_rule_effectiveness"]
    CaseNote = deps["CaseNote"]
    CaseEvent = deps["CaseEvent"]
    Simulation = deps["Simulation"]
    Indicator = deps["Indicator"]
    LIVE_EVENTS = deps["LIVE_EVENTS"]
    _parse_event_time = deps["_parse_event_time"]
    FEATURE_MODULES = deps["FEATURE_MODULES"]
    _require_roles = deps["_require_roles"]
    IndicatorRelation = deps["IndicatorRelation"]
    _run_simulation_for_user = deps["_run_simulation_for_user"]
    update_analytics_report = deps["update_analytics_report"]
    _severity_from_score = deps["_severity_from_score"]
    db = deps["db"]

    def _module_default_settings(module_id):
        return module_default_settings(module_id)

    def _module_settings_for_user(user_id, module_id):
        return module_settings_for_user(user_id, module_id, FeatureModuleSetting)

    def _feature_module_preview(user_id, module_id, settings):
        return feature_module_preview(
            user_id,
            module_id,
            settings,
            {
                "build_history": deps["_build_history"],
                "calculate_analytics": calculate_analytics,
                "compute_rule_effectiveness": _compute_rule_effectiveness,
                "Case": Case,
                "CaseNote": CaseNote,
                "CaseEvent": CaseEvent,
                "Simulation": Simulation,
                "Indicator": Indicator,
                "LIVE_EVENTS": LIVE_EVENTS,
                "parse_event_time": _parse_event_time,
            },
        )

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
        for ind in indicators:
            nodes.append({"id": f"ioc:{ind.id}", "label": f"{ind.indicator_type}:{ind.value}"})
        for rel in relations:
            edges.append({"from": f"ioc:{rel.indicator_id}", "to": f"{rel.relation_type}:{rel.relation_id}", "label": rel.relation_type})
        return jsonify({"nodes": nodes, "edges": edges})

    @app.route("/activity")
    @_require_roles("admin", "analyst")
    def activity_page():
        users = User.query.order_by(User.username.asc()).all()
        rows = []
        for user in users:
            sims = Simulation.query.filter_by(user_id=user.id).all()
            scores = [s.detection_score for s in sims]
            avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
            rows.append(
                {
                    "user": user,
                    "avg_score": avg_score,
                    "sim_count": len(scores),
                    "cases_created": Case.query.filter_by(user_id=user.id).count(),
                    "cases_assigned": Case.query.filter_by(assignee_id=user.id).count(),
                    "notes": CaseNote.query.filter_by(author_id=user.id).count(),
                }
            )
        return render_template("activity.html", rows=rows)

    @app.route("/upgrade", methods=["POST"])
    def upgrade():
        item = request.form.get("item")
        if item in UPGRADES:
            cost = UPGRADES[item]["cost"]
            if session["budget"] >= cost:
                session["budget"] -= cost
                upgrades = session["upgrades"]
                upgrades[UPGRADES[item]["stage"]] += UPGRADES[item]["boost"]
                session["upgrades"] = upgrades
                purchased = session.get("upgrades_purchased", {})
                purchased[item] = purchased.get(item, 0) + 1
                session["upgrades_purchased"] = purchased
                session.modified = True
        return redirect(url_for("dashboard"))

    @app.route("/simulate", methods=["POST"])
    def simulate():
        attack_type = request.form.get("attack")
        variant = request.form.get("variant", "standard")
        events, score, weakest, recs = _run_simulation_for_user(attack_type, session.get("user_id"), variant=variant)
        session["last_result"] = {"attack": attack_type, "score": score, "events": events, "recs": recs}

        user_id = session.get("user_id")
        if user_id:
            try:
                last_sim = Simulation.query.filter_by(user_id=user_id).order_by(Simulation.created_at.desc()).first()
                if last_sim:
                    session["last_sim_id"] = last_sim.id
                update_analytics_report(user_id)
            except Exception as e:
                print(f"Error updating analytics: {e}")

        analytics = calculate_analytics(user_id)
        roi_data = calculate_upgrade_roi()
        try:
            user = User.query.get(user_id) if user_id else None
        except Exception:
            user = None

        return render_template(
            "dashboard.html",
            budget=session["budget"],
            upgrades=session["upgrades"],
            available_upgrades=UPGRADES,
            history=session["history"],
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
            last_sim_id=session.get("last_sim_id"),
            saved_searches=deps["SavedSearch"].query.filter_by(user_id=user_id).order_by(deps["SavedSearch"].created_at.desc()).all(),
            presets=deps["SimulationPreset"].query.filter_by(user_id=user_id).order_by(deps["SimulationPreset"].created_at.desc()).all(),
            schedules=deps["SimulationSchedule"].query.filter_by(user_id=user_id).order_by(deps["SimulationSchedule"].created_at.desc()).all(),
            preset_lookup={p.id: p for p in deps["SimulationPreset"].query.filter_by(user_id=user_id).all()} if user_id else {},
            timeline_days=30,
            cases=Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(10).all(),
            users=User.query.order_by(User.username.asc()).all(),
            widgets=_get_widget_prefs(user_id),
        )

    @app.route("/view_report")
    def view_report():
        report_data = session.get("last_result", {})
        last_sim_id = session.get("last_sim_id")
        if last_sim_id:
            return redirect(url_for("report", sim_id=last_sim_id))
        if not report_data:
            return "No report available. Please run a simulation first.", 400
        report_data["severity"] = _severity_from_score(report_data.get("score", 0))
        return render_template("report_poster.html", report=report_data, ai_enabled=AI_ENABLED)

    @app.route("/report/<int:sim_id>")
    def report(sim_id):
        try:
            sim = Simulation.query.get_or_404(sim_id)
        except Exception:
            return "Report not found", 404
        report_payload = {
            "attack": sim.attack_type,
            "score": sim.detection_score,
            "events": sim.events,
            "recs": sim.ai_recommendations or [],
            "threat_narrative": sim.threat_narrative,
            "severity": _severity_from_score(sim.detection_score),
        }
        return render_template("report_poster.html", report=report_payload, sim=sim, ai_enabled=AI_ENABLED)

    @app.route("/reset")
    def reset():
        session.clear()
        return redirect(url_for("dashboard"))
