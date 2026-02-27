import unittest

from services.history_service import HistoryService


class _DummyCol:
    def __eq__(self, _other):
        return None

    def is_(self, _other):
        return None

    def desc(self):
        return None


class _DummyQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def filter_by(self, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def limit(self, _n):
        return self

    def all(self):
        return self._rows


class _LiveLog:
    user_id = _DummyCol()
    created_at = _DummyCol()
    query = _DummyQuery([])


class _Simulation:
    created_at = _DummyCol()
    query = _DummyQuery([])


class HistoryServiceTests(unittest.TestCase):
    def test_build_history_from_session_for_guest(self):
        fake_session = {
            "data_source": "both",
            "history": [{"attack": "Phishing", "score": 70, "time": "12:10", "events": [], "weakest": []}],
        }
        svc = HistoryService(
            {
                "session": fake_session,
                "LiveLog": _LiveLog,
                "Simulation": _Simulation,
                "or_": lambda *_args: None,
                "live_events": [],
                "expand_chain_event_fn": lambda e: [e],
                "merge_history_fn": lambda a, b: (a or []) + (b or []),
                "extract_event_id_fn": lambda _events: None,
                "is_live_simulation_fn": lambda _sim: False,
            }
        )

        out = svc.build_history(user_id=None)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["attack"], "Phishing")
        self.assertEqual(out[0]["source"], "simulation")


if __name__ == "__main__":
    unittest.main()
