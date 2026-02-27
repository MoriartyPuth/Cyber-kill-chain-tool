from flask import render_template, request, session, redirect, url_for, jsonify


def register_insights_routes(app, deps):
    _build_history = deps["_build_history"]
    calculate_analytics = deps["calculate_analytics"]
    calculate_upgrade_roi = deps["calculate_upgrade_roi"]
    _require_roles = deps["_require_roles"]
    _resource_monitoring = deps["_resource_monitoring"]
    _kpi_dashboard_rows = deps["_kpi_dashboard_rows"]
    _ioc_technique_cooccurrence = deps["_ioc_technique_cooccurrence"]
    AI_ENABLED = deps["AI_ENABLED"]
    User = deps["User"]
    Indicator = deps["Indicator"]
    MITRE_ATTACK_MAPPING = deps["MITRE_ATTACK_MAPPING"]
    db = deps["db"]

    @app.route("/analytics")
    def analytics_api():
        user_id = session.get("user_id")
        data = calculate_analytics(user_id)
        roi = calculate_upgrade_roi()
        return jsonify({"analytics": data, "roi": roi})

    @app.route("/insights/<panel>")
    def insights_panel(panel):
        user_id = session.get("user_id")
        analytics = calculate_analytics(user_id)
        valid = {"timeline", "breakdown", "workflow", "funnel"}
        if panel not in valid:
            return redirect(url_for("dashboard"))
        return render_template("insights_panel.html", panel=panel, analytics=analytics, ai_enabled=AI_ENABLED)

    @app.route("/analytics-panels")
    def analytics_panels_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        timeline_days = int(request.args.get("timeline_days", 30))
        selected_ioc_type = (request.args.get("ioc_type") or "all").strip().lower()
        selected_attack_type = (request.args.get("attack_type") or "all").strip()
        try:
            selected_top_links = int(request.args.get("top_links", 45))
        except Exception:
            selected_top_links = 45
        selected_top_links = max(10, min(100, selected_top_links))

        history = _build_history(user_id)
        analytics = calculate_analytics(user_id, history_override=history, timeline_days=timeline_days)
        ioc_types = sorted([(row[0] or "").lower() for row in db.session.query(Indicator.indicator_type).distinct().all() if row and row[0]])
        attack_types = sorted(list(MITRE_ATTACK_MAPPING.keys()))
        analytics["ioc_technique_network"] = _ioc_technique_cooccurrence(
            user_id=user_id,
            ioc_type=None if selected_ioc_type == "all" else selected_ioc_type,
            attack_type=None if selected_attack_type == "all" else selected_attack_type,
            max_links=selected_top_links,
        )
        try:
            user = User.query.get(user_id)
        except Exception:
            user = None

        return render_template(
            "analytics_panels.html",
            analytics=analytics,
            history=history,
            user=user,
            ai_enabled=AI_ENABLED,
            timeline_days=timeline_days,
            ioc_types=ioc_types,
            attack_types=attack_types,
            selected_ioc_type=selected_ioc_type,
            selected_attack_type=selected_attack_type,
            selected_top_links=selected_top_links,
        )

    @app.route("/eps-dashboard")
    @_require_roles("admin", "analyst")
    def eps_dashboard_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        history = _build_history(user_id)
        analytics = calculate_analytics(user_id, history_override=history, timeline_days=30) or {}
        eps = analytics.get("resource_monitor") or _resource_monitoring(history, user_id=user_id)
        try:
            user = User.query.get(user_id)
        except Exception:
            user = None
        return render_template("eps_dashboard.html", user=user, eps=eps)

    @app.route("/kpi-dashboard")
    @_require_roles("admin", "analyst")
    def kpi_dashboard_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        history = _build_history(user_id)
        rows = _kpi_dashboard_rows(history)
        totals = {
            "rows": len(rows),
            "alarm": sum(r["alarm"] for r in rows),
            "correlation": sum(r["correlation"] for r in rows),
            "incidents": sum(r["inc_alarm"] for r in rows),
        }
        try:
            user = User.query.get(user_id)
        except Exception:
            user = None
        return render_template("kpi_dashboard.html", user=user, kpi_rows=rows, totals=totals)
