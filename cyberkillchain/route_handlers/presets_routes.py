from flask import render_template, request, session, redirect, url_for, flash


def register_presets_routes(app, deps):
    db = deps["db"]
    SimulationPreset = deps["SimulationPreset"]
    SimulationSchedule = deps["SimulationSchedule"]
    Simulation = deps["Simulation"]
    _run_simulation_for_user = deps["_run_simulation_for_user"]

    @app.route("/presets")
    def presets_page():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        presets = SimulationPreset.query.filter_by(user_id=user_id).order_by(SimulationPreset.created_at.desc()).all()
        schedules = SimulationSchedule.query.filter_by(user_id=user_id).order_by(SimulationSchedule.created_at.desc()).all()
        preset_lookup = {p.id: p for p in presets}
        return render_template("presets.html", presets=presets, schedules=schedules, preset_lookup=preset_lookup)

    @app.route("/presets/create", methods=["POST"])
    def create_preset():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        name = (request.form.get("name") or "").strip()
        attack_type = request.form.get("attack_type")
        if not name or not attack_type:
            flash("Preset name and attack type are required.", "error")
            return redirect(url_for("dashboard"))
        try:
            db.session.add(SimulationPreset(user_id=user_id, name=name, attack_type=attack_type))
            db.session.commit()
            flash("Preset created.", "success")
        except Exception as e:
            print(f"Create preset error: {e}")
            db.session.rollback()
            flash("Failed to create preset.", "error")
        return redirect(url_for("dashboard"))

    @app.route("/presets/run/<int:preset_id>", methods=["POST"])
    def run_preset(preset_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        preset = SimulationPreset.query.filter_by(id=preset_id, user_id=user_id).first()
        if not preset:
            return redirect(url_for("dashboard"))
        _run_simulation_for_user(preset.attack_type, user_id, source="preset")
        return redirect(url_for("dashboard"))

    @app.route("/schedules/create", methods=["POST"])
    def create_schedule():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        preset_raw = (request.form.get("preset_id") or "").strip()
        interval_raw = (request.form.get("interval_minutes") or "").strip()
        if not preset_raw:
            flash("Preset and interval are required.", "error")
            return redirect(url_for("dashboard"))
        try:
            preset_id = int(preset_raw)
            interval = int(interval_raw or 60)
        except ValueError:
            flash("Preset and interval must be valid numbers.", "error")
            return redirect(url_for("dashboard"))
        if preset_id <= 0 or interval <= 0:
            flash("Preset and interval are required.", "error")
            return redirect(url_for("dashboard"))
        preset = SimulationPreset.query.filter_by(id=preset_id, user_id=user_id).first()
        if not preset:
            flash("Preset not found.", "error")
            return redirect(url_for("dashboard"))
        try:
            db.session.add(SimulationSchedule(user_id=user_id, preset_id=preset_id, interval_minutes=interval))
            db.session.commit()
            flash("Schedule created. It runs when you access the dashboard.", "info")
        except Exception as e:
            print(f"Create schedule error: {e}")
            db.session.rollback()
            flash("Failed to create schedule.", "error")
        return redirect(url_for("dashboard"))

    @app.route("/schedules/toggle/<int:schedule_id>", methods=["POST"])
    def toggle_schedule(schedule_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        sched = SimulationSchedule.query.filter_by(id=schedule_id, user_id=user_id).first()
        if not sched:
            return redirect(url_for("dashboard"))
        sched.enabled = not sched.enabled
        db.session.add(sched)
        db.session.commit()
        return redirect(url_for("dashboard"))

    @app.route("/simulations/<int:sim_id>/tags", methods=["POST"])
    def tag_simulation(sim_id):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        sim = Simulation.query.filter_by(id=sim_id, user_id=user_id).first()
        if not sim:
            return redirect(url_for("dashboard"))
        raw = (request.form.get("tags") or "").strip()
        tags = [t.strip() for t in raw.split(",") if t.strip()]
        if tags:
            current = sim.tags or []
            sim.tags = sorted(set(current + tags))
            db.session.add(sim)
            db.session.commit()
        return redirect(url_for("report", sim_id=sim_id))
