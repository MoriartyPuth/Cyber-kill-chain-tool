from collections import Counter
from datetime import datetime

from flask import flash, redirect, render_template, request, session, url_for


def register_ops_routes(app, deps):
    db = deps["db"]
    or_ = deps["or_"]

    ThreatSignature = deps["ThreatSignature"]
    ThreatDiscovery = deps["ThreatDiscovery"]
    ThreatSummary = deps["ThreatSummary"]
    ThreatAdvisory = deps["ThreatAdvisory"]
    ThreatSettings = deps["ThreatSettings"]
    AlertRule = deps["AlertRule"]
    UserWidget = deps["UserWidget"]
    AuditLog = deps["AuditLog"]
    Indicator = deps["Indicator"]
    IndicatorRelation = deps["IndicatorRelation"]
    RetentionPolicy = deps["RetentionPolicy"]
    User = deps["User"]

    ai_enabled = deps["AI_ENABLED"]
    ai_advisor = deps["ai_advisor"]
    require_roles = deps["require_roles"]

    get_widget_prefs = deps["get_widget_prefs"]
    record_audit = deps["record_audit"]
    build_advisory_trend = deps["build_advisory_trend"]
    build_threat_summary = deps["build_threat_summary"]
    build_threat_advisories = deps["build_threat_advisories"]
    compute_rule_effectiveness = deps["compute_rule_effectiveness"]
    apply_retention = deps["apply_retention"]

    @app.route("/threats")
    def threats_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        signatures = ThreatSignature.query.order_by(ThreatSignature.last_seen.desc()).limit(50).all()
        discoveries = ThreatDiscovery.query.order_by(ThreatDiscovery.created_at.desc()).limit(50).all()
        summaries = ThreatSummary.query.order_by(ThreatSummary.created_at.desc()).limit(5).all()
        return render_template("threats.html", signatures=signatures, discoveries=discoveries, summaries=summaries)

    @app.route("/threats/advisories")
    def threat_advisory_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        advisories = ThreatAdvisory.query.order_by(ThreatAdvisory.updated_at.desc()).limit(50).all()
        recent = advisories[:6]

        priority_counter = Counter([(a.priority or "medium").lower() for a in advisories])
        status_counter = Counter([(a.status or "open").lower() for a in advisories])
        trend = build_advisory_trend(advisories, days=7)

        priority_labels = ["critical", "high", "medium"]
        priority_values = [priority_counter.get(k, 0) for k in priority_labels]
        status_labels = ["open", "applied", "dismissed"]
        status_values = [status_counter.get(k, 0) for k in status_labels]

        return render_template(
            "threat_advisories.html",
            advisories=advisories,
            recent_advisories=recent,
            priority_labels=priority_labels,
            priority_values=priority_values,
            status_labels=status_labels,
            status_values=status_values,
            trend=trend,
            total_advisories=len(advisories),
            total_open=status_counter.get("open", 0),
            total_applied=status_counter.get("applied", 0),
            total_dismissed=status_counter.get("dismissed", 0),
        )

    @app.route("/threats/mark/<int:signature_id>", methods=["POST"])
    def mark_threat(signature_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        status = (request.form.get("status") or "reviewed").strip()
        sig = ThreatSignature.query.get(signature_id)
        if sig and status in ("new", "reviewed", "ignored"):
            sig.status = status
            db.session.add(sig)
            db.session.commit()
            record_audit(user_id, "threat_marked", {"signature_id": signature_id, "status": status})
        return redirect(url_for("threats_page"))

    @app.route("/threats/summary", methods=["POST"])
    def run_threat_summary():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        discoveries = ThreatDiscovery.query.order_by(ThreatDiscovery.created_at.desc()).limit(20).all()
        if discoveries:
            data = [{"source": d.source, "sample": d.sample} for d in discoveries]
            if ai_enabled:
                summary = ai_advisor.generate_threat_summary(data)
            else:
                summary = build_threat_summary(discoveries)
            db.session.add(ThreatSummary(summary=summary))
            db.session.commit()
            record_audit(user_id, "threat_summary_run", {"count": len(discoveries)})
        return redirect(url_for("threats_page"))

    @app.route("/threats/advisories/generate", methods=["POST"])
    def generate_threat_advisories():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        discoveries = ThreatDiscovery.query.order_by(ThreatDiscovery.created_at.desc()).limit(120).all()
        advisories = build_threat_advisories(discoveries)
        now = datetime.utcnow()

        created = 0
        updated = 0
        for adv in advisories:
            existing = ThreatAdvisory.query.filter_by(advisory_key=adv["advisory_key"]).first()
            if existing:
                existing.title = adv["title"]
                existing.priority = adv["priority"]
                existing.summary = adv["summary"]
                existing.recommended_actions = adv["recommended_actions"]
                existing.signal_count = adv["signal_count"]
                existing.updated_at = now
                db.session.add(existing)
                updated += 1
            else:
                db.session.add(
                    ThreatAdvisory(
                        advisory_key=adv["advisory_key"],
                        title=adv["title"],
                        priority=adv["priority"],
                        summary=adv["summary"],
                        recommended_actions=adv["recommended_actions"],
                        signal_count=adv["signal_count"],
                        status="open",
                        created_at=now,
                        updated_at=now,
                    )
                )
                created += 1

        db.session.commit()
        record_audit(
            user_id,
            "threat_advisories_generated",
            {"created": created, "updated": updated, "source_count": len(discoveries)},
        )
        return redirect(url_for("threats_page"))

    @app.route("/threats/advisories/<int:advisory_id>/status", methods=["POST"])
    def update_threat_advisory_status(advisory_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        status = (request.form.get("status") or "open").strip().lower()
        if status not in ("open", "applied", "dismissed"):
            status = "open"

        advisory = ThreatAdvisory.query.get(advisory_id)
        if advisory:
            advisory.status = status
            advisory.updated_at = datetime.utcnow()
            db.session.add(advisory)
            db.session.commit()
            record_audit(user_id, "threat_advisory_status_updated", {"advisory_id": advisory_id, "status": status})
        return redirect(url_for("threats_page"))

    @app.route("/settings")
    def settings_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        prefs = get_widget_prefs(user_id)
        settings = ThreatSettings.query.first()
        rules = AlertRule.query.filter(or_(AlertRule.user_id == user_id, AlertRule.user_id.is_(None))).order_by(AlertRule.created_at.desc()).all()
        return render_template("settings.html", prefs=prefs, settings=settings, alert_rules=rules, data_source=session.get("data_source", "both"))

    @app.route("/settings/widgets", methods=["POST"])
    def update_widgets():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        keys = ["analytics", "summary", "history", "search_results"]
        selected = set(request.form.getlist("widgets"))
        UserWidget.query.filter_by(user_id=user_id).delete()
        for key in keys:
            db.session.add(UserWidget(user_id=user_id, widget_key=key, enabled=(key in selected)))
        db.session.commit()
        record_audit(user_id, "widgets_updated", {"enabled": list(selected)})
        return redirect(url_for("settings_page"))

    @app.route("/settings/threats", methods=["POST"])
    def update_threat_settings():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        threshold = (request.form.get("anomaly_threshold") or "").strip()
        auto_case = request.form.get("auto_case") == "on"
        settings = ThreatSettings.query.first()
        if not settings:
            settings = ThreatSettings()
        if threshold.isdigit():
            settings.anomaly_threshold = int(threshold)
        settings.auto_case = auto_case
        db.session.add(settings)
        db.session.commit()
        record_audit(user_id, "threat_settings_updated", {"anomaly_threshold": settings.anomaly_threshold, "auto_case": settings.auto_case})
        return redirect(url_for("settings_page"))

    @app.route("/settings/data-source", methods=["POST"])
    def update_data_source():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        source = (request.form.get("data_source") or "both").strip().lower()
        if source not in ("live", "simulation", "both"):
            source = "live"
        session["data_source"] = source
        session.modified = True
        record_audit(user_id, "data_source_updated", {"data_source": source})
        return redirect(url_for("settings_page"))

    @app.route("/settings/alerts", methods=["POST"])
    def create_alert_rule():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Alert rule name is required.", "error")
            return redirect(url_for("settings_page"))
        rule = AlertRule(
            user_id=user_id,
            name=name,
            attack_type=(request.form.get("attack_type") or "").strip() or None,
            stage=(request.form.get("stage") or "").strip() or None,
            status=(request.form.get("status") or "Missed").strip(),
            severity_threshold=(request.form.get("severity_threshold") or "medium").strip().lower(),
            auto_case=request.form.get("auto_case") == "on",
            enabled=True,
        )
        db.session.add(rule)
        db.session.commit()
        record_audit(user_id, "alert_rule_created", {"rule_id": rule.id})
        return redirect(url_for("settings_page"))

    @app.route("/settings/alerts/toggle/<int:rule_id>", methods=["POST"])
    def toggle_alert_rule(rule_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        rule = AlertRule.query.filter_by(id=rule_id, user_id=user_id).first()
        if rule:
            rule.enabled = not rule.enabled
            db.session.add(rule)
            db.session.commit()
        return redirect(url_for("settings_page"))

    @app.route("/settings/alerts/delete/<int:rule_id>", methods=["POST"])
    def delete_alert_rule(rule_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        rule = AlertRule.query.filter_by(id=rule_id, user_id=user_id).first()
        if rule:
            db.session.delete(rule)
            db.session.commit()
            record_audit(user_id, "alert_rule_deleted", {"rule_id": rule_id})
        return redirect(url_for("settings_page"))

    @app.route("/audit")
    @require_roles("admin", "analyst")
    def audit_page():
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
        return render_template("audit.html", logs=logs)

    @app.route("/intel")
    @require_roles("admin", "analyst")
    def intel_page():
        indicators = Indicator.query.order_by(Indicator.last_seen.desc()).limit(200).all()
        relations = IndicatorRelation.query.order_by(IndicatorRelation.created_at.desc()).limit(200).all()
        return render_template("intel.html", indicators=indicators, relations=relations)

    @app.route("/rule-effectiveness")
    @require_roles("admin", "analyst")
    def rule_effectiveness_page():
        user_id = session.get("user_id")
        metrics = compute_rule_effectiveness(user_id, lookback_days=30, trend_days=14)
        rules = metrics.get("rules") or []

        selected_rule_id = request.args.get("rule_id", type=int)
        if not selected_rule_id and rules:
            selected_rule_id = rules[0]["id"]

        selected_rule = next((r for r in rules if r["id"] == selected_rule_id), None)
        if not selected_rule and rules:
            selected_rule = rules[0]

        return render_template(
            "rule_effectiveness.html",
            rules=rules,
            top_noisy=metrics.get("top_noisy") or [],
            event_count=metrics.get("event_count") or 0,
            trend_labels=metrics.get("trend_labels") or [],
            selected_rule=selected_rule,
        )

    @app.route("/admin/retention", methods=["POST"])
    @require_roles("admin")
    def update_retention():
        sims = (request.form.get("simulations_days") or "").strip()
        audits = (request.form.get("audit_days") or "").strip()
        live_logs = (request.form.get("live_logs_days") or "").strip()
        enabled = request.form.get("enabled") == "on"
        policy = RetentionPolicy.query.first()
        if not policy:
            policy = RetentionPolicy()
        policy.simulations_days = int(sims) if sims.isdigit() else policy.simulations_days
        policy.audit_days = int(audits) if audits.isdigit() else policy.audit_days
        policy.live_logs_days = int(live_logs) if live_logs.isdigit() else (policy.live_logs_days or 30)
        policy.enabled = enabled
        db.session.add(policy)
        db.session.commit()
        apply_retention()
        record_audit(
            session.get("user_id"),
            "retention_updated",
            {
                "simulations_days": policy.simulations_days,
                "audit_days": policy.audit_days,
                "live_logs_days": policy.live_logs_days,
                "enabled": policy.enabled,
            },
        )
        return redirect(url_for("admin_users"))

    @app.route("/admin/users", methods=["GET", "POST"])
    @require_roles("admin")
    def admin_users():
        if request.method == "POST":
            user_id = int(request.form.get("user_id", 0))
            role = request.form.get("role")
            if role not in ("admin", "analyst", "viewer"):
                return redirect(url_for("admin_users"))
            user = User.query.get(user_id)
            if user:
                user.role = role
                db.session.add(user)
                db.session.commit()
                record_audit(session.get("user_id"), "role_updated", {"target_user_id": user_id, "role": role})
            return redirect(url_for("admin_users"))

        users = User.query.order_by(User.created_at.desc()).all()
        policy = RetentionPolicy.query.first()
        audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
        return render_template("admin_users.html", users=users, policy=policy, audit_logs=audit_logs)
