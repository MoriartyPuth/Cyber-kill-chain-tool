from datetime import datetime, timedelta


class SimulationService:
    def __init__(self, deps=None):
        deps = deps or {}
        self.db = deps.get("db")
        self.session = deps.get("session")
        self.Simulation = deps.get("Simulation")
        self.SimulationSchedule = deps.get("SimulationSchedule")
        self.SimulationPreset = deps.get("SimulationPreset")
        self.UpgradePurchase = deps.get("UpgradePurchase")
        self.AnalyticsReport = deps.get("AnalyticsReport")
        self.upgrades = deps.get("UPGRADES") or {}
        self.ai_enabled = deps.get("AI_ENABLED", False)
        self.ai_advisor = deps.get("ai_advisor")
        self.get_simulation_fn = deps.get("get_simulation_fn")
        self.get_simulation_with_upgrades_fn = deps.get("get_simulation_with_upgrades_fn")
        self.index_simulation_events_fn = deps.get("index_simulation_events_fn")
        self.record_threat_discovery_fn = deps.get("record_threat_discovery_fn")

    def calculate_upgrade_roi(self):
        upgrades_purchased = self.session.get("upgrades_purchased", {})
        roi_data = {}
        for upgrade_name, count in upgrades_purchased.items():
            if upgrade_name in self.upgrades and count > 0:
                cost = self.upgrades[upgrade_name]["cost"] * count
                roi_data[upgrade_name] = {
                    "cost": cost,
                    "units": count,
                    "roi_multiplier": self.upgrades[upgrade_name]["roi"],
                    "total_roi": cost * self.upgrades[upgrade_name]["roi"],
                }
        return roi_data

    def update_analytics_report(self, user_id, skip_ai=False):
        try:
            report = self.AnalyticsReport.query.filter_by(user_id=user_id).first()
            if not report:
                report = self.AnalyticsReport(user_id=user_id)

            simulations = self.Simulation.query.filter_by(user_id=user_id).all()
            if simulations:
                scores = [s.detection_score for s in simulations]
                report.total_simulations = len(simulations)
                report.average_score = sum(scores) / len(scores)
                report.max_score = max(scores)
                report.min_score = min(scores)

                attack_breakdown = {}
                for sim in simulations:
                    attack_breakdown.setdefault(sim.attack_type, []).append(sim.detection_score)
                report.attack_breakdown = {attack: sum(vals) // len(vals) for attack, vals in attack_breakdown.items()}

                if report.attack_breakdown:
                    report.strongest_defense = max(report.attack_breakdown, key=report.attack_breakdown.get)
                    report.weakest_defense = min(report.attack_breakdown, key=report.attack_breakdown.get)

                upgrades = self.UpgradePurchase.query.filter_by(user_id=user_id).all()
                report.total_invested = sum(u.cost for u in upgrades)

                if self.ai_enabled and report.total_simulations >= 3 and not skip_ai and self.ai_advisor:
                    try:
                        insights = self.ai_advisor.analyze_defense_strategy(
                            report.total_simulations, report.average_score, report.attack_breakdown, report.total_invested
                        )
                        report.ai_insights = insights
                    except Exception as e:
                        print(f"Error generating AI insights: {e}")

            self.db.session.add(report)
            self.db.session.commit()
        except Exception as e:
            print(f"Error updating analytics: {e}")
            self.db.session.rollback()

    def run_simulation_for_user(self, attack_type, user_id, source="manual", variant="standard"):
        events, score, weakest, recs = self.get_simulation_fn(attack_type, variant=variant)

        if user_id:
            sim = self.Simulation(
                user_id=user_id,
                attack_type=attack_type,
                detection_score=score,
                events=events,
                weakest_stages=weakest,
                variant=variant,
            )
            if self.ai_enabled and self.ai_advisor:
                try:
                    sim.threat_narrative = self.ai_advisor.generate_threat_narrative(attack_type, score, events)
                    sim.ai_recommendations = self.ai_advisor.generate_intelligent_recommendations(
                        attack_type, score, weakest, self.session.get("upgrades", {})
                    )
                except Exception as e:
                    print(f"Error generating AI insights: {e}")
            self.db.session.add(sim)
            self.db.session.commit()

        history = self.session.get("history", [])
        history.insert(
            0,
            {
                "attack": attack_type,
                "score": score,
                "time": datetime.now().strftime("%H:%M"),
                "events": events,
                "weakest": weakest,
                "source": source,
            },
        )
        self.session["history"] = history
        self.session.modified = True

        if self.index_simulation_events_fn:
            self.index_simulation_events_fn(attack_type, score, events, user_id=user_id)
        if self.record_threat_discovery_fn:
            for ev in events:
                self.record_threat_discovery_fn(
                    "simulation",
                    {
                        "attack_type": attack_type,
                        "stage": ev.get("stage"),
                        "tool": ev.get("tool"),
                        "status": ev.get("status"),
                        "reason": ev.get("reason"),
                        "miss_reason": ev.get("miss_reason"),
                    },
                )
        return events, score, weakest, recs

    def run_simulation_for_user_bg(self, attack_type, user_id):
        events, score, weakest, _ = self.get_simulation_with_upgrades_fn(attack_type, {})
        sim = self.Simulation(user_id=user_id, attack_type=attack_type, detection_score=score, events=events, weakest_stages=weakest)
        self.db.session.add(sim)
        self.db.session.commit()
        if self.index_simulation_events_fn:
            self.index_simulation_events_fn(attack_type, score, events, user_id=user_id)
        return events, score

    def run_due_schedules(self, user_id, run_simulation_fn):
        if not user_id:
            return
        now = datetime.utcnow()
        schedules = self.SimulationSchedule.query.filter_by(user_id=user_id, enabled=True).all()
        for sched in schedules:
            last = sched.last_run_at or (now - timedelta(minutes=sched.interval_minutes + 1))
            due = last + timedelta(minutes=sched.interval_minutes)
            if due <= now:
                preset = self.SimulationPreset.query.get(sched.preset_id)
                if preset:
                    try:
                        run_simulation_fn(preset.attack_type, user_id, source="schedule")
                        sched.last_run_at = now
                        self.db.session.add(sched)
                        self.db.session.commit()
                    except Exception as e:
                        print(f"Scheduled run failed: {e}")
                        self.db.session.rollback()
                break

    def run_due_schedules_background(self, run_bg_fn):
        now = datetime.utcnow()
        schedules = self.SimulationSchedule.query.filter_by(enabled=True).all()
        for sched in schedules:
            last = sched.last_run_at or (now - timedelta(minutes=sched.interval_minutes + 1))
            due = last + timedelta(minutes=sched.interval_minutes)
            if due <= now:
                preset = self.SimulationPreset.query.get(sched.preset_id)
                if preset:
                    try:
                        run_bg_fn(preset.attack_type, sched.user_id)
                        sched.last_run_at = now
                        self.db.session.add(sched)
                        self.db.session.commit()
                    except Exception as e:
                        print(f"Background schedule failed: {e}")
                        self.db.session.rollback()
