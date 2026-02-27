import hashlib
import ipaddress
import json
from collections import Counter
from datetime import datetime, timedelta


class CaseThreatService:
    def __init__(self, deps):
        self.db = deps["db"]
        self.session = deps["session"]
        self.Case = deps["Case"]
        self.CaseNote = deps["CaseNote"]
        self.CaseEvent = deps["CaseEvent"]
        self.CaseChecklistItem = deps["CaseChecklistItem"]
        self.AuditLog = deps["AuditLog"]
        self.UserWidget = deps["UserWidget"]
        self.ThreatSignature = deps["ThreatSignature"]
        self.ThreatDiscovery = deps["ThreatDiscovery"]
        self.ThreatSettings = deps["ThreatSettings"]
        self.Indicator = deps["Indicator"]
        self.recommendations_map = deps["recommendations_map"]
        self.compliance_checklists = deps["compliance_checklists"]
        self.build_history_fn = deps["build_history_fn"]
        self.calculate_analytics_fn = deps["calculate_analytics_fn"]
        self.parse_event_time_fn = deps["parse_event_time_fn"]

    def record_audit(self, actor_id, action, meta=None):
        try:
            self.db.session.add(self.AuditLog(actor_id=actor_id, action=action, meta=meta or {}))
            self.db.session.commit()
        except Exception as e:
            print(f"Audit log failed: {e}")
            self.db.session.rollback()

    def record_case_event(self, case_id, actor_id, action, meta=None):
        try:
            self.db.session.add(self.CaseEvent(case_id=case_id, actor_id=actor_id, action=action, meta=meta or {}))
            self.db.session.commit()
        except Exception as e:
            print(f"Case event log failed: {e}")
            self.db.session.rollback()

    def ensure_case_checklist(self, case_id):
        existing = self.CaseChecklistItem.query.filter_by(case_id=case_id).count()
        if existing:
            return
        for fw, items in self.compliance_checklists.items():
            for item in items:
                self.db.session.add(self.CaseChecklistItem(case_id=case_id, framework=fw, item=item, status="open"))
        self.db.session.commit()

    def weekly_report_data(self, days=7):
        history = self.build_history_fn(self.session.get("user_id"))
        cutoff = datetime.utcnow() - timedelta(days=days)
        filtered = []
        for h in history:
            ts = self.parse_event_time_fn(h.get("_ts") or h.get("time"))
            if ts and ts >= cutoff:
                filtered.append(h)
        total = len(filtered)
        if not total:
            return {"days": days, "total": 0}
        attacks = {}
        misses = {}
        for h in filtered:
            attacks[h.get("attack")] = attacks.get(h.get("attack"), 0) + 1
            for e in h.get("events") or []:
                if e.get("status") in ("Missed", "Not Observed"):
                    misses[e.get("stage")] = misses.get(e.get("stage"), 0) + 1
        top_attacks = sorted(attacks.items(), key=lambda x: x[1], reverse=True)[:5]
        top_misses = sorted(misses.items(), key=lambda x: x[1], reverse=True)[:5]
        analytics = self.calculate_analytics_fn(self.session.get("user_id"))
        return {
            "days": days,
            "total": total,
            "top_attacks": top_attacks,
            "top_misses": top_misses,
            "avg_score": analytics.get("avg_score") if analytics else 0,
            "kill_chain_gaps": analytics.get("kill_chain_gaps") if analytics else [],
        }

    def get_widget_prefs(self, user_id):
        keys = ["analytics", "summary", "history", "search_results"]
        prefs = {k: True for k in keys}
        if not user_id:
            return prefs
        rows = self.UserWidget.query.filter_by(user_id=user_id).all()
        if not rows:
            return prefs
        for row in rows:
            if row.widget_key in prefs:
                prefs[row.widget_key] = bool(row.enabled)
        return prefs

    @staticmethod
    def threat_fingerprint(payload):
        base = {
            "attack_type": payload.get("attack_type"),
            "stage": payload.get("stage") or payload.get("kill_chain_stage"),
            "tool": payload.get("tool"),
            "status": payload.get("status") or ("Detected" if payload.get("detected") else "Missed"),
            "reason": payload.get("reason") or payload.get("description") or payload.get("miss_reason"),
        }
        raw = json.dumps(base, sort_keys=True).lower()
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def record_threat_discovery(self, source, payload):
        fingerprint = self.threat_fingerprint(payload)
        now = datetime.utcnow()
        sig = self.ThreatSignature.query.filter_by(fingerprint=fingerprint).first()
        settings = self.ThreatSettings.query.first()
        threshold = settings.anomaly_threshold if settings else 2
        auto_case = settings.auto_case if settings else True

        if not sig:
            sig = self.ThreatSignature(fingerprint=fingerprint, count=1, first_seen=now, last_seen=now, status="new")
            self.db.session.add(sig)
            self.db.session.commit()
            self.db.session.add(self.ThreatDiscovery(signature_id=sig.id, source=source, sample=payload))
            self.db.session.commit()
            if auto_case and self.session.get("user_id"):
                case = self.Case(
                    user_id=self.session.get("user_id"),
                    title="Auto-case: new threat pattern",
                    description=f"Discovered new threat pattern from {source}.",
                    status="Investigating",
                    severity="Critical",
                )
                self.db.session.add(case)
                self.db.session.commit()
            return sig, True

        sig.count += 1
        sig.last_seen = now
        self.db.session.add(sig)
        self.db.session.commit()
        if sig.count <= threshold:
            self.db.session.add(self.ThreatDiscovery(signature_id=sig.id, source=source, sample=payload))
            self.db.session.commit()
        return sig, False

    @staticmethod
    def enrich_ip(ip_value):
        try:
            ip_obj = ipaddress.ip_address(ip_value)
            if ip_obj.is_private:
                ip_type = "private"
            elif ip_obj.is_loopback:
                ip_type = "loopback"
            elif ip_obj.is_multicast:
                ip_type = "multicast"
            else:
                ip_type = "public"
            return {"ip_type": ip_type}
        except Exception:
            return {"ip_type": "invalid"}

    @staticmethod
    def extract_iocs(log):
        iocs = []
        if log.get("source_ip"):
            iocs.append({"type": "ip", "value": log.get("source_ip")})
        if log.get("dest_ip"):
            iocs.append({"type": "ip", "value": log.get("dest_ip")})
        if log.get("domain"):
            iocs.append({"type": "domain", "value": log.get("domain")})
        if log.get("url"):
            iocs.append({"type": "url", "value": log.get("url")})
        if log.get("file_hash"):
            iocs.append({"type": "hash", "value": log.get("file_hash")})
        if log.get("hash"):
            iocs.append({"type": "hash", "value": log.get("hash")})
        if log.get("email"):
            iocs.append({"type": "email", "value": log.get("email")})
        if log.get("sender"):
            iocs.append({"type": "email", "value": log.get("sender")})
        return iocs

    @staticmethod
    def default_expiry(indicator_type):
        if indicator_type == "ip":
            return datetime.utcnow() + timedelta(days=30)
        if indicator_type == "url":
            return datetime.utcnow() + timedelta(days=14)
        return datetime.utcnow() + timedelta(days=90)

    def record_indicator(self, indicator_type, value, source="log", attack_type=None, stage=None, confidence=0.5):
        if not value:
            return None
        enrichment = self.enrich_ip(value) if indicator_type == "ip" else {}
        now = datetime.utcnow()
        indicator = self.Indicator.query.filter_by(indicator_type=indicator_type, value=value).first()
        if not indicator:
            indicator = self.Indicator(
                indicator_type=indicator_type,
                value=value,
                enrichment=enrichment,
                confidence=confidence,
                status="new",
                source=source,
                last_seen_attack=attack_type,
                last_seen_stage=stage,
                count=1,
                first_seen=now,
                last_seen=now,
                expires_at=self.default_expiry(indicator_type),
            )
            self.db.session.add(indicator)
        else:
            indicator.count += 1
            indicator.last_seen = now
            indicator.enrichment = enrichment
            indicator.last_seen_attack = attack_type or indicator.last_seen_attack
            indicator.last_seen_stage = stage or indicator.last_seen_stage
            self.db.session.add(indicator)
        self.db.session.commit()
        return indicator

    @staticmethod
    def build_threat_summary(discoveries):
        lines = []
        for d in discoveries[:5]:
            sample = d.sample or {}
            line = f"- {sample.get('attack_type') or 'Unknown'} at {sample.get('stage') or sample.get('kill_chain_stage')}: {sample.get('tool') or 'Unknown tool'}"
            lines.append(line)
        if not lines:
            return "No new threats discovered."
        return "New threat patterns observed:\n" + "\n".join(lines)

    def build_threat_advisories(self, discoveries, max_items=6):
        grouped = {}
        for d in discoveries:
            sample = d.sample or {}
            attack_type = sample.get("attack_type") or "Unknown"
            stage = sample.get("stage") or sample.get("kill_chain_stage") or "Unknown"
            status_value = (sample.get("status") or ("Detected" if sample.get("detected") else "Missed")).strip().lower()
            key = f"{attack_type}|{stage}"
            if key not in grouped:
                grouped[key] = {
                    "attack_type": attack_type,
                    "stage": stage,
                    "total": 0,
                    "missed": 0,
                    "tools": Counter(),
                    "sources": Counter(),
                }
            g = grouped[key]
            g["total"] += 1
            if status_value == "missed":
                g["missed"] += 1
            if sample.get("tool"):
                g["tools"][sample.get("tool")] += 1
            g["sources"][d.source or "unknown"] += 1

        if not grouped:
            return []

        advisories = []
        for g in grouped.values():
            miss_rate = (g["missed"] / g["total"]) if g["total"] else 0.0
            if g["missed"] >= 4 or (g["total"] >= 3 and miss_rate >= 0.75):
                priority = "critical"
            elif g["missed"] >= 2 or (g["total"] >= 3 and miss_rate >= 0.5):
                priority = "high"
            else:
                priority = "medium"

            top_tool = g["tools"].most_common(1)[0][0] if g["tools"] else "multiple tools"
            source_text = ", ".join([f"{k}:{v}" for k, v in g["sources"].most_common(2)])
            stage_recs = self.recommendations_map.get(g["stage"], {})
            actions = [
                stage_recs.get("improve") or "Harden control coverage for this stage.",
                stage_recs.get("response") or "Run immediate containment and verification playbooks.",
            ]

            advisory_key = hashlib.sha256(
                json.dumps({"attack_type": g["attack_type"], "stage": g["stage"]}, sort_keys=True).encode("utf-8")
            ).hexdigest()

            advisories.append(
                {
                    "advisory_key": advisory_key,
                    "title": f"{g['attack_type']} exposure at {g['stage']}",
                    "priority": priority,
                    "summary": (
                        f"Observed {g['total']} related signals with {g['missed']} misses "
                        f"({int(miss_rate * 100)}% miss rate). Most common tooling: {top_tool}. "
                        f"Primary sources: {source_text or 'unknown'}."
                    ),
                    "recommended_actions": actions,
                    "signal_count": g["total"],
                }
            )

        order = {"critical": 0, "high": 1, "medium": 2}
        advisories.sort(key=lambda a: (order.get(a["priority"], 9), -a["signal_count"]))
        return advisories[:max_items]

    @staticmethod
    def build_advisory_trend(advisories, days=7):
        today = datetime.utcnow().date()
        labels = []
        values = []
        for d in range(days - 1, -1, -1):
            day = today - timedelta(days=d)
            labels.append(day.strftime("%m-%d"))
            values.append(0)
        idx = {label: i for i, label in enumerate(labels)}
        for advisory in advisories:
            created = advisory.created_at.date() if advisory.created_at else today
            label = created.strftime("%m-%d")
            if label in idx:
                values[idx[label]] += 1
        return {"labels": labels, "values": values}
