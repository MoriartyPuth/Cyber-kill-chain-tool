from datetime import datetime


class HistoryService:
    def __init__(self, deps=None):
        deps = deps or {}
        self.session = deps.get("session")
        self.LiveLog = deps.get("LiveLog")
        self.Simulation = deps.get("Simulation")
        self.or_ = deps.get("or_")
        self.live_events = deps.get("live_events")
        self.parse_event_time_fn = deps.get("parse_event_time_fn")
        self.expand_chain_event_fn = deps.get("expand_chain_event_fn")
        self.merge_history_fn = deps.get("merge_history_fn")
        self.extract_event_id_fn = deps.get("extract_event_id_fn")
        self.is_live_simulation_fn = deps.get("is_live_simulation_fn")

    def build_live_db_history(self, user_id=None, limit=500):
        history = []
        try:
            query = self.LiveLog.query
            if user_id:
                query = query.filter(self.or_(self.LiveLog.user_id == user_id, self.LiveLog.user_id.is_(None)))
            else:
                query = query.filter(self.LiveLog.user_id.is_(None))
            rows = query.order_by(self.LiveLog.created_at.desc()).limit(limit).all()
            for row in rows:
                event = {}
                chain_events = []
                severity = None
                if isinstance(row.payload, dict):
                    payload = row.payload
                    event = payload.get("event") or row.mapped_event or {}
                    chain_events = payload.get("chain_events") or (self.expand_chain_event_fn(event) if event else [])
                    severity = payload.get("severity") or event.get("severity")
                else:
                    event = row.mapped_event or {}
                    chain_events = self.expand_chain_event_fn(event) if event else []
                    severity = event.get("severity")

                status = event.get("status")
                score = 100 if status == "Detected" else 0
                weakest = [e.get("stage") for e in chain_events if e.get("status") == "Missed"]
                history.append(
                    {
                        "id": None,
                        "attack": (row.raw_log or {}).get("attack_type") or event.get("attack_type"),
                        "score": score,
                        "time": row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else "",
                        "events": chain_events,
                        "weakest": weakest,
                        "severity": severity,
                        "source": "live",
                        "event_id": event.get("event_id"),
                        "_ts": row.created_at.isoformat() if row.created_at else None,
                    }
                )
        except Exception as e:
            print(f"Error fetching LiveLog history: {e}")
            history = []
        return history

    def build_history(self, user_id=None):
        data_source = self.session.get("data_source", "both")
        live_history = []
        if self.live_events:
            for ev in list(self.live_events):
                event = ev.get("event") or {}
                status = event.get("status")
                score = 100 if status == "Detected" else 0
                chain_events = ev.get("chain_events") or [event]
                weakest = [e.get("stage") for e in chain_events if e.get("status") == "Missed"]
                live_history.append(
                    {
                        "id": None,
                        "attack": ev.get("attack"),
                        "score": score,
                        "time": ev.get("timestamp") or (ev.get("ts") or "")[:16],
                        "events": chain_events,
                        "weakest": weakest,
                        "severity": ev.get("severity"),
                        "source": "live",
                        "event_id": event.get("event_id"),
                        "_ts": ev.get("ts"),
                    }
                )

        live_db_history = self.build_live_db_history(user_id=user_id)
        live_history = self.merge_history_fn(live_history, live_db_history)

        history = []
        if user_id:
            try:
                sims = self.Simulation.query.filter_by(user_id=user_id).order_by(self.Simulation.created_at.desc()).all()
                for sim in sims:
                    src = "live" if self.is_live_simulation_fn(sim) else "simulation"
                    history.append(
                        {
                            "id": sim.id,
                            "attack": sim.attack_type,
                            "score": sim.detection_score,
                            "time": sim.created_at.strftime("%Y-%m-%d %H:%M"),
                            "events": sim.events,
                            "weakest": sim.weakest_stages or [],
                            "source": src,
                            "event_id": self.extract_event_id_fn(sim.events),
                            "_ts": sim.created_at.isoformat() if sim.created_at else None,
                        }
                    )
            except Exception as e:
                print(f"Error fetching DB history for analytics: {e}")
                history = self.session.get("history", [])
        else:
            raw = self.session.get("history", [])
            for h in raw:
                events = h.get("events", [])
                history.append(
                    {
                        "id": None,
                        "attack": h.get("attack"),
                        "score": h.get("score"),
                        "time": datetime.now().strftime("%Y-%m-%d ") + h.get("time", ""),
                        "events": events,
                        "weakest": h.get("weakest", []),
                        "source": h.get("source") or "simulation",
                        "event_id": self.extract_event_id_fn(events),
                        "_ts": None,
                    }
                )

        if data_source in ("live", "simulation", "both"):
            return self.merge_history_fn(live_history, history)
        return self.merge_history_fn(live_history, history)
