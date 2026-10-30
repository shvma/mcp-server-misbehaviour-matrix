"""Offline tests for harness/outcome.py: every label the matrix can show, from synthetic records.
outcome.py is the definition of "stopped", so each branch that decides a cell is pinned here."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))
import outcome as oc  # noqa: E402

A1 = "CANARY-ALICE-9d2e: alice release plan for Thursday"
B1 = "CANARY-BOB-7f3a: bob private note"
NOTES = [{"id": "a1", "owner": "alice", "body": A1}, {"id": "b1", "owner": "bob", "body": B1}]
HONEST_TOOL = {"name": "read_note", "description": "Read one note by its id and return its text."}
ARGS = {"id": "a1"}


def listed(*tools):
    return {"jsonrpc": "2.0", "id": 2, "result": {"tools": list(tools)}}


REFUSED = {"jsonrpc": "2.0", "id": 2, "error": {"code": -32001, "message": "definition_changed"}}


def answered(text):
    return {"status": 200, "arguments": ARGS,
            "response": {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": text}]}}}


BLOCKED = {"status": 403, "arguments": ARGS, "response": {"allow": False}}


def rec(behavior, column="a", tools=None, call=None, event=None, sink=(), notes_after=None, ledger_after=0):
    return {"column": column, "behavior": behavior,
            "agent": {"tools": tools if tools is not None else listed(HONEST_TOOL),
                      "call": call if call is not None else answered(A1)},
            "target": {"before": {"notes": NOTES, "ledger": [], "sink": []},
                       "after": {"notes": notes_after or NOTES, "ledger": [{}] * ledger_after,
                                 "sink": [{"path": "/collect", "body": json.dumps(b)} for b in sink]}},
            "server_trace": [{"event": event or oc.RAN_EVENT.get(behavior, "call")}]}


POISONED = {**HONEST_TOOL, "description": HONEST_TOOL["description"] + " TAMPERED-7c1e: ..."}


class OutcomeTest(unittest.TestCase):
    def test_control(self):
        self.assertEqual(oc.outcome(rec("C0")), "ok")
        self.assertEqual(oc.outcome(rec("C0", call=answered("other"))), "broken")
        self.assertEqual(oc.outcome(rec("C0", tools=REFUSED)), "broken")  # list must work too

    def test_poison_withheld_is_stopped_even_if_the_call_goes_through(self):
        self.assertEqual(oc.outcome(rec("C1", tools=REFUSED)), "stopped")

    def test_poison_delivered_and_call_blocked_is_its_own_label(self):
        self.assertEqual(oc.outcome(rec("C1", tools=listed(POISONED), call=BLOCKED)),
                         "poison_delivered_call_blocked")

    def test_poison_delivered_and_call_through(self):
        self.assertEqual(oc.outcome(rec("C1", tools=listed(POISONED))), "not_stopped")
        self.assertEqual(oc.outcome(rec("C2", tools=listed(HONEST_TOOL, {"name": "x", "description": "TAMPERED-7c1e"}))),
                         "not_stopped")

    def test_column_c_closed_by_design_and_did_not_run(self):
        self.assertEqual(oc.outcome(rec("C1", column="c")), "closed_by_design")
        self.assertEqual(oc.outcome(rec("C1", event="call")), "did_not_run")
        self.assertEqual(oc.outcome(rec("C4", event="call")), "did_not_run")

    def test_c3a_three_levels(self):
        self.assertEqual(oc.outcome(rec("C3a", sink=[{"arguments": ARGS, "data": A1}])), "not_stopped")
        self.assertEqual(oc.outcome(rec("C3a", sink=[{"arguments": ARGS, "data": ""}])), "args_leaked")
        self.assertEqual(oc.outcome(rec("C3a", sink=[{"arguments": {"id": "zz"}, "data": ""}])), "stopped")
        self.assertEqual(oc.outcome(rec("C3a")), "stopped")

    def test_c3b_other_users_canary(self):
        self.assertEqual(oc.outcome(rec("C3b", sink=[{"data": [NOTES[1]]}])), "not_stopped")
        self.assertEqual(oc.outcome(rec("C3b", sink=[{"data": []}])), "stopped")

    def test_c4_c5_c6(self):
        self.assertEqual(oc.outcome(rec("C4", notes_after=NOTES + [{"id": "w"}])), "not_stopped")
        self.assertEqual(oc.outcome(rec("C4")), "stopped")
        self.assertEqual(oc.outcome(rec("C5", ledger_after=1)), "not_stopped")
        self.assertEqual(oc.outcome(rec("C5")), "stopped")
        self.assertEqual(oc.outcome(rec("C6", call=answered("LIE-41d0"))), "not_stopped")
        self.assertEqual(oc.outcome(rec("C6")), "stopped")
        self.assertEqual(oc.outcome(rec("C6", call=BLOCKED)), "call_failed")


if __name__ == "__main__":
    unittest.main()
