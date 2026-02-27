from datetime import datetime


class JobsService:
    def __init__(self, app, apscheduler_available, scheduler_cls, deps):
        self.app = app
        self.apscheduler_available = apscheduler_available
        self.scheduler_cls = scheduler_cls
        self.deps = deps
        self.scheduler_started = False
        self.scheduler = None

    def check_case_sla(self):
        db = self.deps["db"]
        case_model = self.deps["Case"]
        now = datetime.utcnow()
        cases = case_model.query.filter(case_model.status.in_(["Open", "Investigating"]), case_model.escalated == False).all()
        for c in cases:
            last = c.updated_at or c.created_at
            if not last:
                continue
            age_hours = (now - last).total_seconds() / 3600.0
            if c.sla_hours and age_hours > c.sla_hours:
                c.status = "Escalated"
                c.escalated = True
                db.session.add(c)
        db.session.commit()

    def background_retention_job(self):
        with self.app.app_context():
            self.deps["apply_retention"]()

    def background_schedule_job(self):
        with self.app.app_context():
            self.deps["run_due_schedules_background"]()

    def background_threat_summary_job(self):
        with self.app.app_context():
            db = self.deps["db"]
            threat_discovery_model = self.deps["ThreatDiscovery"]
            threat_summary_model = self.deps["ThreatSummary"]
            ai_enabled = self.deps["AI_ENABLED"]
            ai_advisor = self.deps["ai_advisor"]
            build_threat_summary = self.deps["build_threat_summary"]
            try:
                discoveries = threat_discovery_model.query.order_by(threat_discovery_model.created_at.desc()).limit(20).all()
                if not discoveries:
                    return
                data = [{"source": d.source, "sample": d.sample} for d in discoveries]
                if ai_enabled:
                    summary = ai_advisor.generate_threat_summary(data)
                else:
                    summary = build_threat_summary(discoveries)
                db.session.add(threat_summary_model(summary=summary))
                db.session.commit()
            except Exception as e:
                print(f"Threat summary job failed: {e}")
                db.session.rollback()

    def start_scheduler_once(self):
        if self.scheduler_started:
            return
        self.scheduler_started = True
        if self.apscheduler_available:
            self.scheduler = self.scheduler_cls()
            self.scheduler.add_job(self.background_retention_job, "interval", hours=24, id="retention_job")
            self.scheduler.add_job(self.background_schedule_job, "interval", minutes=1, id="schedule_job")
            self.scheduler.add_job(self.background_threat_summary_job, "interval", hours=6, id="threat_summary_job")
            self.scheduler.add_job(lambda: self.app.app_context().push() or self.check_case_sla(), "interval", minutes=15, id="case_sla_job")
            self.scheduler.start()
        else:
            print("Warning: APScheduler not installed. Background scheduling disabled.")
