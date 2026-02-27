import base64
import json
import os
import urllib.request


class ESSearchService:
    def __init__(self, received_logs, build_history_fn):
        self.received_logs = received_logs
        self.build_history_fn = build_history_fn
        self.es_url = os.getenv("ELASTICSEARCH_URL")
        self.es_user = os.getenv("ELASTICSEARCH_USERNAME")
        self.es_pass = os.getenv("ELASTICSEARCH_PASSWORD")
        self.es_api_key = os.getenv("ELASTICSEARCH_API_KEY")
        self.es_log_index = os.getenv("ELASTICSEARCH_LOG_INDEX", "cyberkill-logs")
        self.es_sim_index = os.getenv("ELASTICSEARCH_SIM_INDEX", "cyberkill-sims")

    def _es_enabled(self):
        return bool(self.es_url)

    def _es_headers(self):
        headers = {"Content-Type": "application/json"}
        if self.es_api_key:
            headers["Authorization"] = f"ApiKey {self.es_api_key}"
        elif self.es_user and self.es_pass:
            token = base64.b64encode(f"{self.es_user}:{self.es_pass}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        return headers

    def _es_request(self, method, path, body=None):
        if not self._es_enabled():
            return None
        url = self.es_url.rstrip("/") + "/" + path.lstrip("/")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in self._es_headers().items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                raw = resp.read().decode("utf-8") or "{}"
                return json.loads(raw)
        except Exception as e:
            print(f"Elasticsearch request failed: {e}")
            return None

    def _es_index(self, index, doc):
        return self._es_request("POST", f"{index}/_doc", doc)

    def _es_search(self, index, query, size=25):
        body = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": [
                        "attack_type^2",
                        "stage",
                        "status",
                        "tool",
                        "reason",
                        "miss_reason",
                        "description",
                        "kill_chain_stage",
                        "source",
                    ],
                }
            },
            "size": size,
            "sort": [{"@timestamp": "desc"}],
        }
        return self._es_request("POST", f"{index}/_search", body)

    @staticmethod
    def _normalize_hit(source):
        return {
            "type": source.get("source", "unknown"),
            "time": source.get("@timestamp"),
            "attack": source.get("attack_type"),
            "stage": source.get("stage") or source.get("kill_chain_stage"),
            "status": source.get("status") or ("Detected" if source.get("detected") else "Missed"),
            "tool": source.get("tool"),
            "details": source.get("reason") or source.get("description") or source.get("miss_reason"),
        }

    def index_simulation_events(self, attack_type, score, events, user_id=None, now_iso=None):
        if not self._es_enabled():
            return
        ts = now_iso
        if not ts:
            from datetime import datetime
            ts = datetime.utcnow().isoformat()
        for ev in events:
            doc = {
                "@timestamp": ts,
                "source": "simulation",
                "attack_type": attack_type,
                "score": score,
                "stage": ev.get("stage"),
                "status": ev.get("status"),
                "tool": ev.get("tool"),
                "reason": ev.get("reason"),
                "miss_reason": ev.get("miss_reason"),
                "user_id": user_id,
            }
            self._es_index(self.es_sim_index, doc)

    def index_live_log(self, log, mapped_event, now_iso=None):
        if not self._es_enabled():
            return
        ts = now_iso
        if not ts:
            from datetime import datetime
            ts = datetime.utcnow().isoformat()
        doc = {
            "@timestamp": ts,
            "source": "live_log",
            "attack_type": log.get("attack_type"),
            "kill_chain_stage": log.get("kill_chain_stage"),
            "tool": log.get("tool"),
            "detected": log.get("detected"),
            "description": log.get("description"),
            "miss_reason": log.get("miss_reason"),
            "stage": mapped_event.get("stage"),
            "status": mapped_event.get("status"),
        }
        self._es_index(self.es_log_index, doc)

    def search_all(self, query, user_id=None, limit=25):
        results = []
        if self._es_enabled():
            for idx in (self.es_sim_index, self.es_log_index):
                resp = self._es_search(idx, query, size=limit)
                hits = (((resp or {}).get("hits") or {}).get("hits")) or []
                for hit in hits:
                    src = hit.get("_source") or {}
                    results.append(self._normalize_hit(src))
        else:
            q = (query or "").lower()
            history = self.build_history_fn(user_id)
            for h in history:
                for ev in h.get("events", []):
                    hay = json.dumps({"attack": h.get("attack"), "score": h.get("score"), "event": ev}).lower()
                    if q in hay:
                        results.append(
                            {
                                "type": "simulation",
                                "time": h.get("time"),
                                "attack": h.get("attack"),
                                "stage": ev.get("stage"),
                                "status": ev.get("status"),
                                "tool": ev.get("tool"),
                                "details": ev.get("reason") or ev.get("miss_reason"),
                            }
                        )
            for log in self.received_logs:
                hay = json.dumps(log).lower()
                if q in hay:
                    results.append(
                        {
                            "type": "live_log",
                            "time": log.get("timestamp"),
                            "attack": log.get("attack_type"),
                            "stage": log.get("kill_chain_stage"),
                            "status": "Detected" if log.get("detected") else "Missed",
                            "tool": log.get("tool"),
                            "details": log.get("description") or log.get("miss_reason"),
                        }
                    )

        return results[:limit]
