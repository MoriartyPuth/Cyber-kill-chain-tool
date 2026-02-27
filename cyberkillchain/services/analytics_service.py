from datetime import datetime, timedelta



import hashlib
import json
from collections import Counter


class AnalyticsService:
    def __init__(self, deps=None):
        deps = deps or {}
        self.MITRE_ATTACK_MAPPING = deps.get("MITRE_ATTACK_MAPPING") or {}
        self.kill_chain_data = deps.get("kill_chain_data") or []
        self.Indicator = deps.get("Indicator")
        self.LiveLog = deps.get("LiveLog")
        self.AlertRule = deps.get("AlertRule")
        self.or_ = deps.get("or_")
        self.build_history_fn = deps.get("build_history_fn")
        self.parse_event_time_fn = deps.get("parse_event_time_fn")
        self.normalize_severity_fn = deps.get("normalize_severity_fn")
        self.severity_rank_fn = deps.get("severity_rank_fn")
        self.attack_severity = deps.get("ATTACK_SEVERITY") or {}


    def parse_history_time(self, ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            try:
                return datetime.strptime(ts, "%Y-%m-%d %H:%M")
            except Exception:
                return None

    def rolling_avg(self, history, days=7):
        if not history:
            return 0
        now = datetime.utcnow()
        cutoff = now - timedelta(days=days)
        vals = []
        for h in history:
            ts = self.parse_history_time(h.get("_ts") or h.get("time"))
            if ts and ts >= cutoff:
                vals.append(h.get("score", 0) or 0)
        if not vals:
            return 0
        return int(sum(vals) / len(vals))

    def prev_rolling_avg(self, history, days=7):
        if not history:
            return 0
        now = datetime.utcnow()
        end = now - timedelta(days=days)
        start = now - timedelta(days=days * 2)
        vals = []
        for h in history:
            ts = self.parse_history_time(h.get("_ts") or h.get("time"))
            if ts and start <= ts < end:
                vals.append(h.get("score", 0) or 0)
        if not vals:
            return 0
        return int(sum(vals) / len(vals))

    def case_timeline(self, history, days=30):
        now = datetime.utcnow()
        labels = []
        counts = []
        for i in range(days - 1, -1, -1):
            d = (now - timedelta(days=i)).date()
            labels.append(d.strftime("%m-%d"))
            counts.append(0)

        index = {labels[i]: i for i in range(len(labels))}
        for h in history:
            ts = self.parse_history_time(h.get("_ts") or h.get("time"))
            if not ts:
                continue
            key = ts.date().strftime("%m-%d")
            if key in index:
                counts[index[key]] += 1

        return {"labels": labels, "counts": counts, "values": counts}

    def case_breakdown(self, history):
        buckets = {"Created": 0, "Found": 0, "Analyzed": 0}
        for h in history:
            evs = h.get("events") or []
            if not evs:
                buckets["Created"] += 1
                continue
            detected = any((e.get("status") == "Detected") for e in evs)
            missed = any((e.get("status") in ("Missed", "Not Observed")) for e in evs)
            if detected:
                buckets["Found"] += 1
            if missed:
                buckets["Analyzed"] += 1
            if not detected and not missed:
                buckets["Created"] += 1

        return {"counts": buckets}

    def workflow_analysis(self, history):
        counts = {"Detected": 0, "Missed": 0, "Not Observed": 0}
        for h in history:
            for e in (h.get("events") or []):
                st = (e.get("status") or "").strip()
                if st in counts:
                    counts[st] += 1
        return {"counts": counts}

    def threat_analysis_funnel(self, history):
        created = len(history)
        found = 0
        analyzed = 0

        for h in history:
            evs = h.get("events") or []
            if any((e.get("status") == "Detected") for e in evs):
                found += 1
            if any((e.get("status") in ("Missed", "Not Observed")) for e in evs):
                analyzed += 1

        return {
            "labels": ["Created", "Found", "Analyzed"],
            "values": [created, found, analyzed],
        }
    def mitre_heatmap(self, history):
        counts = {}
        for h in history:
            attack = h.get("attack")
            for code, name in self.MITRE_ATTACK_MAPPING.get(attack, []):
                key = f"{code} {name}"
                counts[key] = counts.get(key, 0) + 1
        items = [{"technique": k, "count": v} for k, v in counts.items()]
        items.sort(key=lambda x: x["count"], reverse=True)
        return items

    def mitre_coverage(self, history):
        all_techniques = set()
        for _, items in self.MITRE_ATTACK_MAPPING.items():
            for code, name in items:
                all_techniques.add(f"{code} {name}")
        seen = set()
        for h in history:
            attack = h.get("attack")
            for code, name in self.MITRE_ATTACK_MAPPING.get(attack, []):
                seen.add(f"{code} {name}")
        total = len(all_techniques) or 1
        coverage = round((len(seen) / total) * 100, 1)
        gaps = sorted(list(all_techniques - seen))
        return {"coverage": coverage, "total": total, "seen": len(seen), "gaps": gaps}

    def ioc_technique_cooccurrence(self, user_id=None, ioc_type=None, attack_type=None, max_indicators=240, max_links=45):
        query = self.Indicator.query.order_by(self.Indicator.last_seen.desc())
        if ioc_type:
            query = query.filter(self.Indicator.indicator_type == ioc_type)
        if attack_type:
            query = query.filter(self.Indicator.last_seen_attack == attack_type)
        indicators = query.limit(max_indicators).all()

        edge_weights = Counter()
        node_weights = Counter()
        ioc_count = 0

        for ind in indicators:
            attack = (ind.last_seen_attack or "").strip()
            if attack not in self.MITRE_ATTACK_MAPPING:
                continue

            ioc_count += 1
            raw_ioc = f"{ind.indicator_type}:{ind.value}"
            ioc_label = raw_ioc if len(raw_ioc) <= 44 else f"{raw_ioc[:41]}..."
            weight = max(1, min(int(ind.count or 1), 10))

            for code, name in self.MITRE_ATTACK_MAPPING.get(attack, []):
                tech_label = f"{code} {name}"
                edge_weights[(ioc_label, tech_label)] += weight
                node_weights[ioc_label] += weight
                node_weights[tech_label] += weight

        top_edges = sorted(edge_weights.items(), key=lambda kv: kv[1], reverse=True)[:max_links]

        nodes_map = {}
        nodes = []
        links = []

        def _node_id(prefix, label):
            return f"{prefix}:{hashlib.sha1(label.encode('utf-8')).hexdigest()[:10]}"

        for (ioc_label, tech_label), weight in top_edges:
            if ioc_label not in nodes_map:
                nid = _node_id("ioc", ioc_label)
                nodes_map[ioc_label] = nid
                nodes.append({"id": nid, "label": ioc_label, "type": "ioc", "value": int(node_weights[ioc_label])})
            if tech_label not in nodes_map:
                nid = _node_id("tech", tech_label)
                nodes_map[tech_label] = nid
                nodes.append({"id": nid, "label": tech_label, "type": "technique", "value": int(node_weights[tech_label])})
            links.append({"source": nodes_map[ioc_label], "target": nodes_map[tech_label], "weight": int(weight)})

        return {
            "nodes": nodes,
            "links": links,
            "summary": {
                "indicators_considered": int(ioc_count),
                "cooccurrences": int(len(top_edges)),
                "filters": {
                    "ioc_type": ioc_type or "all",
                    "attack_type": attack_type or "all",
                    "top_links": int(max_links),
                },
            },
        }

    def correlation_matrix(self, history):
        stages = [s[0] for s in self.kill_chain_data]
        index = {s: i for i, s in enumerate(stages)}
        size = len(stages)
        matrix = [[0 for _ in range(size)] for _ in range(size)]

        for h in history:
            evs = h.get("events") or []
            missed = [e.get("stage") for e in evs if e.get("status") == "Missed"]
            for i in range(len(missed)):
                for j in range(i, len(missed)):
                    a, b = missed[i], missed[j]
                    if a in index and b in index:
                        matrix[index[a]][index[b]] += 1
                        if a != b:
                            matrix[index[b]][index[a]] += 1

        return {"stages": stages, "matrix": matrix}

    def kill_chain_gaps(self, history, top_n=3):
        gaps = {s[0]: 0 for s in self.kill_chain_data}
        for h in history:
            evs = h.get("events") or []
            for e in evs:
                status = e.get("status")
                stage = e.get("stage")
                if stage in gaps and status in ("Missed", "Not Observed"):
                    gaps[stage] += 1
        ranked = sorted(gaps.items(), key=lambda x: x[1], reverse=True)
        return [{"stage": s, "count": c} for s, c in ranked[:top_n]]

    def source_compare(self, history):
        live_scores = []
        sim_scores = []
        for h in history:
            if h.get("source") == "live":
                live_scores.append(h.get("score", 0))
            else:
                sim_scores.append(h.get("score", 0))

        def _avg(lst):
            return int(sum(lst) / len(lst)) if lst else 0

        return {
            "live_avg": _avg(live_scores),
            "sim_avg": _avg(sim_scores),
            "live_count": len(live_scores),
            "sim_count": len(sim_scores),
        }

    def resource_monitoring(self, history, user_id=None):
        minute_buckets = {}
        total_events = 0
        detected_events = 0
        missed_events = 0
        total_sims = len(history or [])

        for h in history or []:
            ts = self.parse_event_time_fn(h.get("_ts") or h.get("time"))
            if not ts:
                continue
            minute_key = ts.replace(second=0, microsecond=0)
            evs = h.get("events") or []
            event_count = len(evs)
            total_events += event_count
            minute_buckets[minute_key] = minute_buckets.get(minute_key, 0) + event_count

            for ev in evs:
                status = (ev.get("status") or "").strip()
                if status == "Detected":
                    detected_events += 1
                elif status in ("Missed", "Not Observed"):
                    missed_events += 1

        ordered = sorted(minute_buckets.items(), key=lambda kv: kv[0])[-20:]
        eps_labels = [k.strftime("%m-%d %H:%M") for k, _ in ordered]
        eps_values = [round(v / 60.0, 3) for _, v in ordered]

        avg_eps = round(sum(eps_values) / len(eps_values), 3) if eps_values else 0.0
        peak_eps = max(eps_values) if eps_values else 0.0
        detection_rate = round((detected_events / total_events) * 100, 1) if total_events else 0.0
        noise_rate = round((missed_events / total_events) * 100, 1) if total_events else 0.0
        signal_quality = max(0.0, round(100.0 - noise_rate, 1))
        throughput_health = min(100.0, round(avg_eps * 240, 1))

        day_counts = {}
        today = datetime.utcnow().date()
        for i in range(9, -1, -1):
            d = today - timedelta(days=i)
            day_counts[d.strftime("%Y-%m-%d")] = 0
        for h in history or []:
            ts = self.parse_event_time_fn(h.get("_ts") or h.get("time"))
            if not ts:
                continue
            key = ts.strftime("%Y-%m-%d")
            if key in day_counts:
                day_counts[key] += len(h.get("events") or [])
        daily_labels = list(day_counts.keys())
        daily_eps_values = [round(v / 86400.0, 4) for v in day_counts.values()]

        device_counter = Counter()
        log_type_counter = Counter()
        host_counter = Counter()
        device_volume = Counter()
        log_type_volume = Counter()
        host_volume = Counter()
        raw_timeline = Counter()

        try:
            q = self.LiveLog.query
            if user_id:
                q = q.filter(self.or_(self.LiveLog.user_id == user_id, self.LiveLog.user_id.is_(None)))
            rows = q.order_by(self.LiveLog.created_at.desc()).limit(500).all()
        except Exception:
            rows = []

        for row in rows:
            raw = row.raw_log or {}
            ts = row.created_at
            if ts:
                minute_key = ts.replace(second=0, microsecond=0)
                raw_timeline[minute_key] += 1
            device = str(raw.get("device_type") or raw.get("platform") or raw.get("source") or "unknown")
            log_type = str(raw.get("log_type") or raw.get("tool") or raw.get("kill_chain_stage") or "event")
            host = str(raw.get("host") or raw.get("hostname") or raw.get("source_ip") or raw.get("dest_ip") or "unknown")
            volume_bytes = len(json.dumps(raw, default=str).encode("utf-8"))
            device_counter[device] += 1
            log_type_counter[log_type] += 1
            host_counter[host] += 1
            device_volume[device] += volume_bytes
            log_type_volume[log_type] += volume_bytes
            host_volume[host] += volume_bytes

        def _fmt_bytes(n):
            if n >= 1024 * 1024:
                return f"{round(n / (1024 * 1024), 2)} MB"
            if n >= 1024:
                return f"{round(n / 1024, 1)} KB"
            return f"{int(n)} B"

        def _rows(counter, volume_counter, top_n=6):
            out = []
            for name, count in counter.most_common(top_n):
                out.append({"name": name, "count": int(count), "volume": _fmt_bytes(volume_counter.get(name, 0))})
            return out

        raw_points = sorted(raw_timeline.items(), key=lambda kv: kv[0])[-30:]
        raw_labels = [k.strftime("%m-%d %H:%M") for k, _ in raw_points]
        raw_values = [int(v) for _, v in raw_points]

        return {
            "eps_labels": eps_labels,
            "eps_values": eps_values,
            "daily_labels": daily_labels,
            "daily_eps_values": daily_eps_values,
            "raw_labels": raw_labels,
            "raw_values": raw_values,
            "kpi_labels": ["Detection Rate", "Signal Quality", "Throughput Health"],
            "kpi_values": [detection_rate, signal_quality, throughput_health],
            "device_rows": _rows(device_counter, device_volume),
            "log_type_rows": _rows(log_type_counter, log_type_volume),
            "host_rows": _rows(host_counter, host_volume),
            "totals": {
                "simulations": int(total_sims),
                "events": int(total_events),
                "avg_eps": float(avg_eps),
                "peak_eps": float(peak_eps),
            },
        }

    def kpi_dashboard_rows(self, history):
        grouped = {}
        for h in history or []:
            attack = (h.get("attack") or "Unknown").strip() or "Unknown"
            row = grouped.setdefault(attack, {
                "company": attack,
                "branch": "SOC Main",
                "sim_count": 0,
                "score_sum": 0.0,
                "alarm": 0,
                "correlation": 0,
                "threat": 0,
                "fp_count": 0,
                "use_alarm": 0,
                "use_correlation": 0,
                "use_log": 0,
                "inc_alarm": 0,
                "inc_correlation": 0,
            })
            events = h.get("events") or []
            total_events = len(events)
            detected = 0
            missed = 0
            for ev in events:
                status = (ev.get("status") or "").strip()
                if status == "Detected":
                    detected += 1
                elif status in ("Missed", "Not Observed"):
                    missed += 1

            row["sim_count"] += 1
            row["score_sum"] += float(h.get("score") or 0)
            row["alarm"] += total_events
            row["correlation"] += detected
            row["threat"] += missed
            row["fp_count"] += max(0, total_events - detected - missed)
            row["use_alarm"] += 1
            row["use_correlation"] += 1 if detected > 0 else 0
            row["use_log"] += 1 if (h.get("source") == "live") else 0
            row["inc_alarm"] += 1 if missed > 0 else 0
            row["inc_correlation"] += 1 if float(h.get("score") or 0) < 40 else 0

        rows = []
        for _, r in grouped.items():
            avg_score = (r["score_sum"] / r["sim_count"]) if r["sim_count"] else 0.0
            mttd_min = round(max(0.0, (100.0 - avg_score) / 10.0), 1)
            mttr_hr = round(max(0.0, (100.0 - avg_score) / 25.0), 1)
            rows.append({
                "company": r["company"],
                "branch": r["branch"],
                "mttd_min": mttd_min,
                "mttr_hr": mttr_hr,
                "alarm": int(r["alarm"]),
                "correlation": int(r["correlation"]),
                "threat": int(r["threat"]),
                "fp_count": int(r["fp_count"]),
                "use_alarm": int(r["use_alarm"]),
                "use_correlation": int(r["use_correlation"]),
                "use_log": int(r["use_log"]),
                "inc_alarm": int(r["inc_alarm"]),
                "inc_correlation": int(r["inc_correlation"]),
            })
        rows.sort(key=lambda x: x["alarm"], reverse=True)
        return rows

    def compute_rule_effectiveness(self, user_id, lookback_days=30, trend_days=14):
        rules = self.AlertRule.query.filter(self.or_(self.AlertRule.user_id == user_id, self.AlertRule.user_id.is_(None))).order_by(self.AlertRule.created_at.desc()).all()

        history = self.build_history_fn(user_id)
        cutoff = datetime.utcnow() - timedelta(days=lookback_days)
        events = []

        for h in history:
            ts = self.parse_event_time_fn(h.get("_ts") or h.get("time")) or datetime.utcnow()
            if ts < cutoff:
                continue
            attack = h.get("attack")
            base_severity = self.normalize_severity_fn(h.get("severity") or self.attack_severity.get(attack))
            for ev in (h.get("events") or []):
                status = (ev.get("status") or "").strip()
                if not status:
                    continue
                events.append({
                    "day": ts.strftime("%Y-%m-%d"),
                    "attack": attack,
                    "stage": (ev.get("stage") or "").strip(),
                    "status": status,
                    "severity": self.normalize_severity_fn(ev.get("severity") or base_severity),
                })

        def in_scope(rule, rec):
            if rule.attack_type and rec["attack"] != rule.attack_type:
                return False
            if rule.stage and rec["stage"] != rule.stage:
                return False
            if self.severity_rank_fn(rec["severity"]) < self.severity_rank_fn(rule.severity_threshold):
                return False
            return True

        today = datetime.utcnow().date()
        trend_labels = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(trend_days - 1, -1, -1)]

        per_rule = []
        for rule in rules:
            target_status = (rule.status or "Missed").strip()
            scoped = [rec for rec in events if in_scope(rule, rec)]
            predicted = len(scoped)
            tp = sum(1 for rec in scoped if rec["status"] == target_status)
            fp = max(0, predicted - tp)

            positives = sum(1 for rec in events if rec["status"] == target_status and self.severity_rank_fn(rec["severity"]) >= self.severity_rank_fn(rule.severity_threshold))
            precision = round((tp / predicted) * 100, 1) if predicted else 0.0
            recall = round((tp / positives) * 100, 1) if positives else 0.0

            precision_trend = []
            recall_trend = []
            for day in trend_labels:
                day_scoped = [rec for rec in scoped if rec["day"] == day]
                day_pred = len(day_scoped)
                day_tp = sum(1 for rec in day_scoped if rec["status"] == target_status)
                day_pos = sum(1 for rec in events if rec["day"] == day and rec["status"] == target_status and self.severity_rank_fn(rec["severity"]) >= self.severity_rank_fn(rule.severity_threshold))
                day_precision = round((day_tp / day_pred) * 100, 1) if day_pred else 0.0
                day_recall = round((day_tp / day_pos) * 100, 1) if day_pos else 0.0
                precision_trend.append(day_precision)
                recall_trend.append(day_recall)

            per_rule.append({
                "id": rule.id,
                "name": rule.name,
                "enabled": bool(rule.enabled),
                "attack_type": rule.attack_type or "Any",
                "stage": rule.stage or "Any",
                "status": target_status,
                "severity_threshold": rule.severity_threshold,
                "predicted": predicted,
                "tp": tp,
                "fp": fp,
                "precision": precision,
                "recall": recall,
                "precision_trend": precision_trend,
                "recall_trend": recall_trend,
            })

        top_noisy = sorted([r for r in per_rule if r["predicted"] > 0], key=lambda r: (r["fp"], -r["precision"], r["predicted"]), reverse=True)[:5]

        return {"rules": per_rule, "top_noisy": top_noisy, "event_count": len(events), "trend_labels": trend_labels}


