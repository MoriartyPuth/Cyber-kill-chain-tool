from flask import request, session, jsonify


def register_ai_routes(app, deps):
    AI_ENABLED = deps["AI_ENABLED"]
    ai_advisor = deps["ai_advisor"]
    _build_history = deps["_build_history"]
    _build_live_brief = deps["_build_live_brief"]
    _fallback_recommendation_explain = deps["_fallback_recommendation_explain"]
    _fallback_next_steps = deps["_fallback_next_steps"]
    _fallback_case_summary = deps["_fallback_case_summary"]
    _fallback_root_cause = deps["_fallback_root_cause"]
    _fallback_triage = deps["_fallback_triage"]
    incident_playbooks = deps["incident_playbooks"]
    UPGRADES = deps["UPGRADES"]
    calculate_analytics = deps["calculate_analytics"]
    Case = deps["Case"]
    CaseNote = deps["CaseNote"]
    Simulation = deps["Simulation"]

    @app.route("/ai/insights", methods=["POST"])
    def ai_insights():
        if not AI_ENABLED:
            return jsonify({"error": "AI features not enabled on this instance."}), 503
        payload = request.get_json() or {}
        panel = payload.get("panel")
        stage = (payload.get("stage") or "").lower()
        user_id = session.get("user_id")
        history = _build_history(user_id)
        try:
            if panel == "funnel":
                weakest = ["Actions on Objectives"] if stage == "created" else []
                scores = [h.get("score", 0) for h in history]
                avg_score = int(sum(scores) / len(scores)) if scores else 0
                recs = ai_advisor.generate_intelligent_recommendations("All", avg_score, weakest, session.get("upgrades", {}))
                return jsonify({"recommendations": recs})
            if panel == "strategy":
                scores = [h.get("score", 0) for h in history]
                avg_score = sum(scores) / len(scores) if scores else 0
                total_spent = sum([UPGRADES[k]["cost"] * session.get("upgrades_purchased", {}).get(k, 0) for k in UPGRADES])
                narrative = ai_advisor.analyze_defense_strategy(len(history), avg_score, (calculate_analytics(user_id) or {}).get("attack_breakdown", {}), total_spent)
                return jsonify({"strategy": narrative})
            return jsonify({"error": "Unsupported panel for AI insights"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/ai/live/brief", methods=["POST"])
    def ai_live_brief():
        payload = request.get_json() or {}
        events = (payload.get("events") or [])[:50]
        if not AI_ENABLED:
            return jsonify({"summary": _build_live_brief(events), "ai": False})
        try:
            summary = ai_advisor.summarize_live_events(events)
            return jsonify({"summary": summary, "ai": True})
        except Exception as e:
            return jsonify({"summary": _build_live_brief(events), "ai": False, "error": str(e)})

    @app.route("/ai/recommendations/explain", methods=["POST"])
    def ai_explain_recommendations():
        payload = request.get_json() or {}
        attack_type = payload.get("attack_type")
        event = payload.get("event") or {}
        recommendations = payload.get("recommendations") or []
        if not AI_ENABLED:
            return jsonify({"explanation": _fallback_recommendation_explain(event, recommendations), "ai": False})
        try:
            explanation = ai_advisor.explain_recommendations(attack_type, event, recommendations)
            return jsonify({"explanation": explanation, "ai": True})
        except Exception as e:
            return jsonify({"explanation": _fallback_recommendation_explain(event, recommendations), "ai": False, "error": str(e)})

    @app.route("/ai/next_steps", methods=["POST"])
    def ai_next_steps():
        payload = request.get_json() or {}
        attack_type = payload.get("attack_type")
        event = payload.get("event") or {}
        if not AI_ENABLED:
            return jsonify({"steps": _fallback_next_steps(attack_type), "ai": False})
        try:
            steps = ai_advisor.suggest_next_steps(attack_type, event, incident_playbooks.get(attack_type, {}))
            return jsonify({"steps": steps, "ai": True})
        except Exception as e:
            return jsonify({"steps": _fallback_next_steps(attack_type), "ai": False, "error": str(e)})

    @app.route("/ai/case_summary", methods=["POST"])
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
                {"title": case.title, "description": case.description, "status": case.status, "severity": case.severity},
                [{"note": n.note, "created_at": n.created_at.isoformat()} for n in notes],
                {
                    "attack_type": sim.attack_type,
                    "detection_score": sim.detection_score,
                    "events": sim.events,
                    "weakest_stages": sim.weakest_stages,
                } if sim else None,
            )
            return jsonify({"summary": summary, "ai": True})
        except Exception as e:
            return jsonify({"summary": _fallback_case_summary(case, notes, sim), "ai": False, "error": str(e)})

    @app.route("/ai/root_cause", methods=["POST"])
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

    @app.route("/ai/triage_score", methods=["POST"])
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
                {"attack_type": sim.attack_type, "detection_score": sim.detection_score, "events": sim.events} if sim else None,
            )
            return jsonify({"triage": triage, "ai": True})
        except Exception as e:
            return jsonify({"triage": _fallback_triage(case, sim), "ai": False, "error": str(e)})
