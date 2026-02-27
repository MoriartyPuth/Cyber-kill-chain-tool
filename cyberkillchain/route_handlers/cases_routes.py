import os

from flask import flash, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename


def register_cases_routes(app, deps):
    db = deps["db"]
    Case = deps["Case"]
    CaseNote = deps["CaseNote"]
    CaseAttachment = deps["CaseAttachment"]
    CaseEvent = deps["CaseEvent"]
    CaseChecklistItem = deps["CaseChecklistItem"]
    Simulation = deps["Simulation"]
    User = deps["User"]

    case_templates = deps["CASE_TEMPLATES"]
    incident_playbooks = deps["incident_playbooks"]

    severity_from_score = deps["severity_from_score"]
    ensure_case_checklist = deps["ensure_case_checklist"]
    weekly_report_data = deps["weekly_report_data"]
    record_audit = deps["record_audit"]
    record_case_event = deps["record_case_event"]

    @app.route("/cases")
    def cases_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        history = deps["build_history"](user_id)
        cases = Case.query.filter_by(user_id=user_id).order_by(Case.updated_at.desc()).all()
        users = User.query.order_by(User.username.asc()).all()
        return render_template("cases.html", cases=cases, history=history, users=users)

    @app.route("/cases/create", methods=["POST"])
    def create_case():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        sim_id_raw = (request.form.get("simulation_id") or "").strip()
        assignee_id_raw = (request.form.get("assignee_id") or "").strip()
        status = (request.form.get("status") or "Open").strip()
        sla_raw = (request.form.get("sla_hours") or "").strip()
        template_attack = (request.form.get("template_attack") or "").strip()
        if not title:
            tpl = case_templates.get(template_attack)
            if tpl:
                title = tpl["title"]
                if not description:
                    description = tpl["description"]
                if not sla_raw:
                    sla_raw = str(tpl.get("sla_hours") or "")
            else:
                flash("Case title is required.", "error")
                return redirect(url_for("dashboard"))

        sim_id = int(sim_id_raw) if sim_id_raw.isdigit() else None
        assignee_id = int(assignee_id_raw) if assignee_id_raw.isdigit() else None
        sla_hours = int(sla_raw) if sla_raw.isdigit() else 48
        severity = "Low"
        if sim_id:
            sim = Simulation.query.filter_by(id=sim_id, user_id=user_id).first()
            if sim:
                severity = severity_from_score(sim.detection_score)
            else:
                sim_id = None
        if template_attack and case_templates.get(template_attack):
            severity = case_templates[template_attack].get("severity", severity)

        case = Case(
            user_id=user_id,
            simulation_id=sim_id,
            title=title,
            description=description,
            status=status,
            severity=severity,
            sla_hours=sla_hours,
            assignee_id=assignee_id,
        )
        db.session.add(case)
        db.session.commit()
        record_audit(user_id, "case_created", {"case_id": case.id, "sim_id": sim_id})
        record_case_event(case.id, user_id, "case_created", {"template_attack": template_attack or None})
        return redirect(url_for("case_detail", case_id=case.id))

    @app.route("/cases/<int:case_id>")
    def case_detail(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at.desc()).all()
        attachments = CaseAttachment.query.filter_by(case_id=case_id).order_by(CaseAttachment.created_at.desc()).all()
        events = CaseEvent.query.filter_by(case_id=case_id).order_by(CaseEvent.created_at.desc()).all()
        ensure_case_checklist(case.id)
        checklist = (
            CaseChecklistItem.query.filter_by(case_id=case_id)
            .order_by(CaseChecklistItem.framework.asc(), CaseChecklistItem.id.asc())
            .all()
        )
        users = User.query.order_by(User.username.asc()).all()
        sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
        return render_template(
            "case_detail.html",
            case=case,
            notes=notes,
            users=users,
            sim=sim,
            attachments=attachments,
            events=events,
            checklist=checklist,
        )

    @app.route("/cases/<int:case_id>/update", methods=["POST"])
    def update_case(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        case.status = (request.form.get("status") or case.status).strip()
        case.assignee_id = int(request.form.get("assignee_id")) if (request.form.get("assignee_id") or "").isdigit() else case.assignee_id
        case.description = (request.form.get("description") or case.description or "").strip()
        sla_raw = (request.form.get("sla_hours") or "").strip()
        if sla_raw.isdigit():
            case.sla_hours = int(sla_raw)
        db.session.add(case)
        db.session.commit()
        record_audit(user_id, "case_updated", {"case_id": case.id, "status": case.status, "assignee_id": case.assignee_id})
        record_case_event(case.id, user_id, "case_updated", {"status": case.status, "assignee_id": case.assignee_id})
        return redirect(url_for("case_detail", case_id=case.id))

    @app.route("/cases/<int:case_id>/note", methods=["POST"])
    def add_case_note(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        note = (request.form.get("note") or "").strip()
        if not note:
            return redirect(url_for("case_detail", case_id=case.id))
        db.session.add(CaseNote(case_id=case_id, author_id=user_id, note=note))
        db.session.commit()
        record_audit(user_id, "case_note_added", {"case_id": case.id})
        record_case_event(case.id, user_id, "case_note_added", {"note_preview": note[:120]})
        return redirect(url_for("case_detail", case_id=case.id))

    @app.route("/cases/<int:case_id>/attachment", methods=["POST"])
    def add_case_attachment(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        if "file" not in request.files:
            flash("No file uploaded.", "error")
            return redirect(url_for("case_detail", case_id=case.id))
        file_obj = request.files["file"]
        if not file_obj or not file_obj.filename:
            flash("No file selected.", "error")
            return redirect(url_for("case_detail", case_id=case.id))
        filename = secure_filename(file_obj.filename)
        base_dir = os.path.join(app.instance_path, "uploads", "cases", str(case.id))
        os.makedirs(base_dir, exist_ok=True)
        stored_path = os.path.join(base_dir, filename)
        file_obj.save(stored_path)
        attachment = CaseAttachment(
            case_id=case.id,
            filename=filename,
            stored_path=stored_path,
            content_type=file_obj.mimetype,
            size_bytes=os.path.getsize(stored_path),
            uploaded_by=user_id,
        )
        db.session.add(attachment)
        db.session.commit()
        record_audit(user_id, "case_attachment_added", {"case_id": case.id, "filename": filename})
        record_case_event(case.id, user_id, "attachment_added", {"filename": filename})
        return redirect(url_for("case_detail", case_id=case.id))

    @app.route("/cases/attachment/<int:attachment_id>")
    def download_case_attachment(attachment_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        attachment = CaseAttachment.query.get(attachment_id)
        if not attachment:
            return redirect(url_for("dashboard"))
        case = Case.query.get(attachment.case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        directory = os.path.dirname(attachment.stored_path)
        return send_from_directory(
            directory,
            os.path.basename(attachment.stored_path),
            as_attachment=True,
            download_name=attachment.filename,
        )

    @app.route("/cases/<int:case_id>/checklist", methods=["POST"])
    def update_case_checklist(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        item_id = request.form.get("item_id")
        status = (request.form.get("status") or "open").strip().lower()
        item = CaseChecklistItem.query.filter_by(id=item_id, case_id=case_id).first()
        if item and status in ("open", "done"):
            item.status = status
            db.session.add(item)
            db.session.commit()
            record_case_event(case.id, user_id, "checklist_updated", {"item": item.item, "status": status, "framework": item.framework})
        return redirect(url_for("case_detail", case_id=case.id))

    @app.route("/cases/<int:case_id>/postmortem")
    def case_postmortem(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        events = CaseEvent.query.filter_by(case_id=case_id).order_by(CaseEvent.created_at.asc()).all()
        notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at.asc()).all()
        sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
        lessons = []
        if sim:
            missed = [e.get("stage") for e in (sim.events or []) if e.get("status") == "Missed"]
            if missed:
                lessons.append(f"Improve detection at stages: {', '.join(sorted(set(missed)))}.")
        if not lessons:
            lessons.append("Review alerting thresholds and improve visibility where needed.")
        return render_template("postmortem.html", case=case, events=events, notes=notes, lessons=lessons)

    @app.route("/reports/weekly")
    def weekly_report():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        data = weekly_report_data(days=7)
        return render_template("weekly_report.html", report=data)

    @app.route("/cases/<int:case_id>/playbook/run", methods=["POST"])
    def run_case_playbook(case_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        case = Case.query.get(case_id)
        if not case or case.user_id != user_id:
            return redirect(url_for("dashboard"))
        sim = Simulation.query.get(case.simulation_id) if case.simulation_id else None
        attack_type = (sim.attack_type if sim else request.form.get("attack_type")) or ""
        playbook = incident_playbooks.get(attack_type)
        if not playbook:
            flash("No playbook available for this case.", "error")
            return redirect(url_for("case_detail", case_id=case.id))
        steps = playbook.get("blue_team", [])
        for step in steps:
            db.session.add(CaseNote(case_id=case.id, author_id=user_id, note=f"[Playbook] {step}"))
        db.session.commit()
        record_audit(user_id, "playbook_run", {"case_id": case.id, "attack_type": attack_type})
        record_case_event(case.id, user_id, "playbook_run", {"attack_type": attack_type, "steps": len(steps)})
        return redirect(url_for("case_detail", case_id=case.id))
