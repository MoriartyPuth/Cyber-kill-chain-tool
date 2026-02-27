from flask import render_template, request, session, redirect, url_for, flash


def register_dashboard_routes(app, deps):
    _run_due_schedules = deps["_run_due_schedules"]
    _build_history = deps["_build_history"]
    calculate_analytics = deps["calculate_analytics"]
    calculate_upgrade_roi = deps["calculate_upgrade_roi"]
    SavedSearch = deps["SavedSearch"]
    SimulationPreset = deps["SimulationPreset"]
    SimulationSchedule = deps["SimulationSchedule"]
    User = deps["User"]
    UPGRADES = deps["UPGRADES"]
    incident_playbooks = deps["incident_playbooks"]
    AI_ENABLED = deps["AI_ENABLED"]
    Case = deps["Case"]
    _get_widget_prefs = deps["_get_widget_prefs"]
    search_all = deps["search_all"]
    db = deps["db"]

    @app.route("/")
    def dashboard():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        filter_stage = request.args.get("filter_stage")
        source_override = (request.args.get("data_source") or "").strip().lower()
        if source_override in ("live", "simulation", "both"):
            session["data_source"] = source_override
            session.modified = True
        timeline_days = int(request.args.get("timeline_days", 30))

        _run_due_schedules(user_id)
        history = _build_history(user_id)
        filtered_history = history
        if filter_stage:
            fs = (filter_stage or "").lower()
            if fs == "created":
                filtered_history = [h for h in history if h.get("weakest")]
            elif fs == "found":
                def has_detected(h):
                    evs = h.get("events") or []
                    if evs:
                        return any(e.get("status") == "Detected" for e in evs)
                    return int(h.get("score", 0)) > 0

                filtered_history = [h for h in history if has_detected(h)]

        analytics = calculate_analytics(user_id, history_override=filtered_history, timeline_days=timeline_days)
        roi_data = calculate_upgrade_roi()
        saved_searches = SavedSearch.query.filter_by(user_id=user_id).order_by(SavedSearch.created_at.desc()).all()
        presets = SimulationPreset.query.filter_by(user_id=user_id).order_by(SimulationPreset.created_at.desc()).all()
        schedules = SimulationSchedule.query.filter_by(user_id=user_id).order_by(SimulationSchedule.created_at.desc()).all()
        preset_lookup = {p.id: p for p in presets}
        try:
            user = User.query.get(user_id)
        except Exception:
            user = None

        return render_template(
            "dashboard.html",
            budget=session["budget"],
            upgrades=session["upgrades"],
            available_upgrades=UPGRADES,
            history=filtered_history,
            analytics=analytics,
            roi_data=roi_data,
            incident_playbooks=incident_playbooks,
            user=user,
            ai_enabled=AI_ENABLED,
            last_sim_id=session.get("last_sim_id"),
            filter_stage=filter_stage,
            search_query=request.args.get("q"),
            search_results=None,
            saved_searches=saved_searches,
            presets=presets,
            schedules=schedules,
            preset_lookup=preset_lookup,
            timeline_days=timeline_days,
            cases=Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(10).all(),
            users=User.query.order_by(User.username.asc()).all(),
            widgets=_get_widget_prefs(user_id),
        )

    @app.route("/search")
    def search():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        query = (request.args.get("q") or "").strip()
        if not query:
            return redirect(url_for("dashboard"))

        history = _build_history(user_id)
        timeline_days = int(request.args.get("timeline_days", 30))
        analytics = calculate_analytics(user_id, history_override=history, timeline_days=timeline_days)
        roi_data = calculate_upgrade_roi()
        results = search_all(query, user_id=user_id, limit=25)
        saved_searches = SavedSearch.query.filter_by(user_id=user_id).order_by(SavedSearch.created_at.desc()).all()
        presets = SimulationPreset.query.filter_by(user_id=user_id).order_by(SimulationPreset.created_at.desc()).all()
        schedules = SimulationSchedule.query.filter_by(user_id=user_id).order_by(SimulationSchedule.created_at.desc()).all()
        preset_lookup = {p.id: p for p in presets}
        try:
            user = User.query.get(user_id)
        except Exception:
            user = None

        return render_template(
            "dashboard.html",
            budget=session["budget"],
            upgrades=session["upgrades"],
            available_upgrades=UPGRADES,
            history=history,
            analytics=analytics,
            roi_data=roi_data,
            incident_playbooks=incident_playbooks,
            user=user,
            ai_enabled=AI_ENABLED,
            last_sim_id=session.get("last_sim_id"),
            filter_stage=None,
            search_query=query,
            search_results=results,
            saved_searches=saved_searches,
            presets=presets,
            schedules=schedules,
            preset_lookup=preset_lookup,
            timeline_days=timeline_days,
            cases=Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).limit(10).all(),
            users=User.query.order_by(User.username.asc()).all(),
            widgets=_get_widget_prefs(user_id),
        )

    @app.route("/search/save", methods=["POST"])
    def save_search():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        name = (request.form.get("name") or "").strip()
        query = (request.form.get("query") or "").strip()
        if not name or not query:
            flash("Name and query are required to save a search.", "error")
            return redirect(url_for("search", q=query))
        try:
            db.session.add(SavedSearch(user_id=user_id, name=name, query_text=query))
            db.session.commit()
            flash("Search saved.", "success")
        except Exception as e:
            print(f"Save search error: {e}")
            db.session.rollback()
            flash("Failed to save search.", "error")
        return redirect(url_for("search", q=query))

    @app.route("/search/delete/<int:search_id>", methods=["POST"])
    def delete_search(search_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        search = SavedSearch.query.filter_by(id=search_id, user_id=user_id).first()
        if not search:
            return redirect(url_for("dashboard"))
        db.session.delete(search)
        db.session.commit()
        flash("Saved search removed.", "info")
        return redirect(url_for("dashboard"))
