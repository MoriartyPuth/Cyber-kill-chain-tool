import json
import uuid
from datetime import datetime, timedelta

from flask import Response, jsonify, redirect, render_template, request, session, url_for


def register_live_routes(app, socketio, deps):
    db = deps["db"]
    or_ = deps["or_"]
    ai_enabled = deps["AI_ENABLED"]
    attack_severity = deps["ATTACK_SEVERITY"]
    require_roles = deps["require_roles"]
    live_events = deps["LIVE_EVENTS"]
    received_logs = deps["received_logs"]

    LiveLog = deps["LiveLog"]
    LiveFilter = deps["LiveFilter"]
    AlertRule = deps["AlertRule"]
    Simulation = deps["Simulation"]
    Case = deps["Case"]
    CaseNote = deps["CaseNote"]
    CaseAttachment = deps["CaseAttachment"]

    infer_stage = deps["infer_stage"]
    normalize_severity = deps["normalize_severity"]
    extract_iocs = deps["extract_iocs"]
    record_indicator = deps["record_indicator"]
    map_log_to_event = deps["map_log_to_event"]
    index_live_log = deps["index_live_log"]
    record_threat_discovery = deps["record_threat_discovery"]
    recommendations_for_event = deps["recommendations_for_event"]
    expand_chain_event = deps["expand_chain_event"]
    aggregate_live_chain = deps["aggregate_live_chain"]
    build_live_analysis = deps["build_live_analysis"]
    match_alert_rule = deps["match_alert_rule"]
    create_case_from_event_internal = deps["create_case_from_event_internal"]
    record_audit = deps["record_audit"]
    update_analytics_report = deps["update_analytics_report"]

    @app.route("/live")
    @require_roles("admin", "analyst")
    def live_dashboard():
        return render_template("live_dashboard.html", ai_enabled=ai_enabled)

    @app.route("/live/history")
    @require_roles("admin", "analyst")
    def live_history_view():
        user_id = session.get("user_id")
        try:
            limit = int(request.args.get("limit", 200))
        except Exception:
            limit = 200
        limit = max(20, min(limit, 500))

        minutes = request.args.get("minutes")
        attack_filter = (request.args.get("attack") or "").strip().lower()
        status_filter = (request.args.get("status") or "").strip().lower()
        severity_filter = (request.args.get("severity") or "").strip().lower()

        rows = []
        error = None
        try:
            query = LiveLog.query
            if user_id:
                query = query.filter(or_(LiveLog.user_id == user_id, LiveLog.user_id.is_(None)))
            else:
                query = query.filter(LiveLog.user_id.is_(None))
            if minutes:
                try:
                    m = int(minutes)
                    if m > 0:
                        cutoff = datetime.utcnow() - timedelta(minutes=m)
                        query = query.filter(LiveLog.created_at >= cutoff)
                except Exception:
                    pass

            db_rows = query.order_by(LiveLog.created_at.desc()).limit(limit).all()
            for row in db_rows:
                raw = row.raw_log or {}
                payload = row.payload if isinstance(row.payload, dict) else {}
                event = payload.get("event") or row.mapped_event or {}

                attack = str(payload.get("attack") or raw.get("attack_type") or "Unknown")
                stage = str(event.get("stage") or raw.get("kill_chain_stage") or "")
                status = str(event.get("status") or ("Detected" if raw.get("detected") else "Missed"))
                severity = str(payload.get("severity") or event.get("severity") or raw.get("severity") or "").lower()
                description = str(raw.get("description") or event.get("reason") or "")

                if attack_filter and attack_filter != attack.lower():
                    continue
                if status_filter and status_filter != status.lower():
                    continue
                if severity_filter and severity_filter != severity:
                    continue

                rows.append(
                    {
                        "created_at": row.created_at,
                        "attack": attack,
                        "stage": stage,
                        "status": status,
                        "severity": severity,
                        "tool": raw.get("tool") or raw.get("log_type") or "",
                        "event_id": event.get("event_id") or "",
                        "description": description,
                        "raw": raw,
                    }
                )
        except Exception as e:
            error = str(e)
            rows = []

        return render_template(
            "live_history.html",
            rows=rows,
            error=error,
            limit=limit,
            minutes=minutes or "",
            attack=attack_filter,
            status=status_filter,
            severity=severity_filter,
        )

    @socketio.on("connect")
    def handle_connect():
        print("Client connected")

    @socketio.on("disconnect")
    def handle_disconnect():
        print("Client disconnected")

    def _process_live_log(log, emit_socket=True, save_sim_db=True):
        if not log.get("kill_chain_stage"):
            log["kill_chain_stage"] = infer_stage(log)
        attack_type = log.get("attack_type")
        severity = normalize_severity(log.get("severity") or attack_severity.get(attack_type))
        log["severity"] = severity

        iocs = extract_iocs(log)
        for ioc in iocs:
            try:
                record_indicator(
                    ioc.get("type"),
                    ioc.get("value"),
                    source="log",
                    attack_type=log.get("attack_type"),
                    stage=log.get("kill_chain_stage"),
                    confidence=0.6,
                )
            except Exception as e:
                print(f"Indicator record failed: {e}")

        event = map_log_to_event(log)
        event["event_id"] = str(uuid.uuid4())
        event["severity"] = severity
        index_live_log(log, event)
        record_threat_discovery(
            "log",
            {
                "attack_type": log.get("attack_type"),
                "kill_chain_stage": log.get("kill_chain_stage"),
                "tool": log.get("tool"),
                "detected": log.get("detected"),
                "description": log.get("description"),
                "miss_reason": log.get("miss_reason"),
            },
        )

        detected = 1 if event["status"] == "Detected" else 0
        score = int((detected / 1) * 100)
        weakest = [event["stage"]] if event["status"] == "Missed" else []
        recs = recommendations_for_event(event)

        chain_events = expand_chain_event(event)
        aggregate_chain = aggregate_live_chain(attack_type)

        history = session.get("history", [])
        history.insert(
            0,
            {
                "attack": log.get("attack_type"),
                "score": score,
                "time": datetime.utcnow().strftime("%H:%M"),
                "events": chain_events,
                "weakest": weakest,
                "source": "live",
            },
        )
        session["history"] = history
        session.modified = True

        payload = {
            "attack": attack_type,
            "score": score,
            "event": event,
            "chain_events": chain_events,
            "aggregate_chain": aggregate_chain,
            "recommendations": recs,
            "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
            "severity": severity,
            "iocs": iocs,
            "ts": datetime.utcnow().isoformat(),
            "source": "live",
        }
        payload["analysis"] = build_live_analysis(event, chain_events, aggregate_chain, recs, iocs)
        live_events.appendleft(payload)

        alerts = []
        user_id = session.get("user_id")
        try:
            rules = AlertRule.query.filter_by(enabled=True).all()
            for rule in rules:
                if rule.user_id and rule.user_id != user_id:
                    continue
                if match_alert_rule(rule, payload):
                    alerts.append(
                        {
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "message": f"{rule.name}: {payload.get('attack')} at {event.get('stage')}",
                        }
                    )
                    if rule.auto_case and user_id:
                        create_case_from_event_internal(user_id, payload, title_prefix=f"Rule {rule.name}")
        except Exception as e:
            print(f"Alert rule evaluation failed: {e}")

        if emit_socket:
            socketio.emit("new_log", payload)
            if alerts:
                socketio.emit("alert", {"alerts": alerts})

        if save_sim_db and session.get("user_id"):
            sim = Simulation(
                user_id=session["user_id"],
                attack_type=log.get("attack_type"),
                detection_score=score,
                events=[event],
                weakest_stages=weakest,
                variant="live",
                tags=["live_log"],
            )
            db.session.add(sim)
            db.session.commit()
            try:
                update_analytics_report(session["user_id"], skip_ai=True)
            except Exception as e:
                print(f"Analytics report update failed (live): {e}")

        if save_sim_db:
            try:
                db.session.add(
                    LiveLog(
                        user_id=session.get("user_id"),
                        raw_log=log,
                        mapped_event=event,
                        payload=payload,
                    )
                )
                db.session.commit()
            except Exception as e:
                print(f"Live log persistence failed: {e}")
                db.session.rollback()

        return payload, event, score, weakest, recs

    @app.route("/api/logs", methods=["POST"])
    def receive_logs():
        log = request.get_json()
        if not log:
            return jsonify({"error": "Invalid log"}), 400
        required = ["attack_type", "tool", "detected", "description"]
        for key in required:
            if key not in log or log.get(key) in (None, ""):
                return jsonify({"error": f"Missing field: {key}"}), 400
        if not isinstance(log.get("detected"), (bool, int)):
            return jsonify({"error": "Field 'detected' must be boolean"}), 400

        received_logs.append(log)
        _, event, _, _, recs = _process_live_log(log, emit_socket=True, save_sim_db=True)

        return jsonify(
            {
                "status": "log processed",
                "mapped_event": event,
                "recommendations": recs,
            }
        ), 200

    @app.route("/api/live/replay")
    def live_replay():
        limit = request.args.get("limit", 50)
        minutes = request.args.get("minutes")
        try:
            limit = int(limit)
        except Exception:
            limit = 50
        limit = max(1, min(limit, 200))
        events = []
        try:
            query = LiveLog.query
            if session.get("user_id"):
                query = query.filter(or_(LiveLog.user_id == session.get("user_id"), LiveLog.user_id.is_(None)))
            else:
                query = query.filter(LiveLog.user_id.is_(None))
            if minutes:
                m = int(minutes)
                cutoff = datetime.utcnow() - timedelta(minutes=m)
                query = query.filter(LiveLog.created_at >= cutoff)
            rows = query.order_by(LiveLog.created_at.desc()).limit(limit).all()
            for row in rows:
                if isinstance(row.payload, dict):
                    payload = dict(row.payload)
                    event = payload.get("event") or row.mapped_event or {}
                    chain_events = payload.get("chain_events") or (expand_chain_event(event) if event else [])
                    aggregate_chain = payload.get("aggregate_chain") or chain_events
                    recs = payload.get("recommendations") or recommendations_for_event(event)
                    iocs = payload.get("iocs") or extract_iocs(row.raw_log or {})

                    payload.setdefault("chain_events", chain_events)
                    payload.setdefault("aggregate_chain", aggregate_chain)
                    payload.setdefault("recommendations", recs)
                    payload.setdefault("iocs", iocs)
                    if not payload.get("analysis"):
                        payload["analysis"] = build_live_analysis(event, chain_events, aggregate_chain, recs, iocs)
                    events.append(payload)
                else:
                    event = row.mapped_event or {}
                    chain_events = expand_chain_event(event) if event else []
                    recs = recommendations_for_event(event)
                    iocs = extract_iocs(row.raw_log or {})
                    payload = {
                        "attack": (row.raw_log or {}).get("attack_type"),
                        "event": event,
                        "timestamp": row.created_at.strftime("%H:%M:%S") if row.created_at else "",
                        "ts": row.created_at.isoformat() if row.created_at else None,
                        "source": "live",
                        "chain_events": chain_events,
                        "aggregate_chain": chain_events,
                        "recommendations": recs,
                        "iocs": iocs,
                    }
                    payload["analysis"] = build_live_analysis(event, chain_events, chain_events, recs, iocs)
                    events.append(payload)
        except Exception as e:
            print(f"Live replay DB load failed: {e}")
            events = list(live_events)
            if minutes:
                try:
                    m = int(minutes)
                    cutoff = datetime.utcnow() - timedelta(minutes=m)
                    filtered = []
                    for ev in events:
                        ts = ev.get("ts")
                        if not ts:
                            continue
                        try:
                            if datetime.fromisoformat(ts) >= cutoff:
                                filtered.append(ev)
                        except Exception:
                            continue
                    events = filtered
                except Exception:
                    pass
        return jsonify({"events": events[:limit]})

    @app.route("/api/live/correlations")
    def live_correlations():
        groups = {}
        for ev in list(live_events):
            for ioc in ev.get("iocs") or []:
                key = f"{ioc.get('type')}:{ioc.get('value')}"
                entry = groups.setdefault(
                    key,
                    {
                        "type": ioc.get("type"),
                        "value": ioc.get("value"),
                        "count": 0,
                        "attacks": set(),
                        "stages": set(),
                    },
                )
                entry["count"] += 1
                entry["attacks"].add(ev.get("attack"))
                entry["stages"].add((ev.get("event") or {}).get("stage"))
        items = []
        for item in groups.values():
            items.append(
                {
                    "type": item["type"],
                    "value": item["value"],
                    "count": item["count"],
                    "attacks": sorted([a for a in item["attacks"] if a]),
                    "stages": sorted([s for s in item["stages"] if s]),
                }
            )
        items.sort(key=lambda x: x["count"], reverse=True)
        return jsonify({"correlations": items[:50]})

    @app.route("/api/live/filters", methods=["GET", "POST", "DELETE"])
    def live_filters():
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401
        if request.method == "GET":
            rows = LiveFilter.query.filter_by(user_id=user_id).order_by(LiveFilter.created_at.desc()).all()
            return jsonify({"filters": [{"id": row.id, "name": row.name, "filters": row.filters} for row in rows]})

        if request.method == "POST":
            payload = request.get_json() or {}
            name = (payload.get("name") or "").strip()
            filters = payload.get("filters") or {}
            if not name:
                return jsonify({"error": "Name is required"}), 400
            row = LiveFilter(user_id=user_id, name=name, filters=filters)
            db.session.add(row)
            db.session.commit()
            try:
                socketio.emit("live_filters_updated", {"action": "saved", "id": row.id})
            except Exception:
                pass
            return jsonify({"status": "saved", "id": row.id})

        payload = request.get_json() or {}
        fid = payload.get("id")
        if not fid:
            return jsonify({"error": "id required"}), 400
        row = LiveFilter.query.filter_by(id=fid, user_id=user_id).first()
        if row:
            db.session.delete(row)
            db.session.commit()
            try:
                socketio.emit("live_filters_updated", {"action": "deleted", "id": fid})
            except Exception:
                pass
        return jsonify({"status": "deleted"})

    @app.route("/cases/create_from_event", methods=["POST"])
    def create_case_from_event():
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401
        payload = request.get_json() or {}
        case = create_case_from_event_internal(user_id, payload)
        record_audit(user_id, "case_created_live", {"case_id": case.id})
        return jsonify({"status": "created", "case_id": case.id})

    @app.route("/cases/export/<int:case_id>")
    def export_case(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at.asc()).all()
        attachments = CaseAttachment.query.filter_by(case_id=case_id).order_by(CaseAttachment.created_at.asc()).all()
        sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
        data = {
            "case": {
                "id": case.id,
                "title": case.title,
                "description": case.description,
                "status": case.status,
                "severity": case.severity,
                "sla_hours": case.sla_hours,
                "created_at": case.created_at.isoformat() if case.created_at else None,
                "updated_at": case.updated_at.isoformat() if case.updated_at else None,
            },
            "notes": [{"created_at": note.created_at.isoformat(), "note": note.note} for note in notes],
            "attachments": [
                {
                    "filename": attachment.filename,
                    "content_type": attachment.content_type,
                    "size_bytes": attachment.size_bytes,
                    "created_at": attachment.created_at.isoformat(),
                }
                for attachment in attachments
            ],
            "simulation": {
                "id": sim.id,
                "attack_type": sim.attack_type,
                "detection_score": sim.detection_score,
                "events": sim.events,
                "weakest_stages": sim.weakest_stages,
            }
            if sim
            else None,
        }
        resp = Response(json.dumps(data, indent=2), mimetype="application/json")
        resp.headers["Content-Disposition"] = f"attachment; filename=case_{case_id}.json"
        return resp
