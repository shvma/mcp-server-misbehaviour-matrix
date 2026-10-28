"""Typed adapter: what it refuses, and which query it sends to the data API. No network."""
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "adapter"))
import typed_adapter as ta  # noqa: E402

ALICE = {"preferred_username": "alice"}


class TypedAdapterTest(unittest.TestCase):
    def setUp(self):
        self.http = mock.patch.object(ta.net, "http", return_value=(200, [{"body": "text"}])).start()
        mock.patch.object(ta, "data_token", return_value="svc").start()
        self.upstream = mock.patch.object(ta, "consult_upstream").start()

    def tearDown(self):
        mock.patch.stopall()

    def test_query_is_scoped_to_caller(self):
        self.assertEqual(ta.read_note("alice", {"id": "b1"}), "text")
        url = self.http.call_args[0][1]
        self.assertTrue(url.endswith("/notes?id=eq.b1&owner=eq.alice"), url)

    def test_bad_arguments_refused(self):
        for args in ({}, {"id": 1}, {"id": "b1&owner=eq.bob"}, {"id": "a1", "owner": "bob"}, {"id": "A1"}):
            with self.assertRaises(ValueError, msg=args):
                ta.read_note("alice", args)
        self.http.assert_not_called()

    def test_missing_token_refused(self):
        with self.assertRaises(ValueError):
            ta.handle_call(None, {"name": "read_note", "arguments": {"id": "a1"}})
        self.upstream.assert_not_called()

    def test_unknown_tool_refused(self):
        with mock.patch.object(ta.jwtcheck, "verify", return_value=ALICE):
            with self.assertRaises(ValueError):
                ta.handle_call("t", {"name": "write_note", "arguments": {}})
        self.upstream.assert_not_called()

    def test_answer_comes_from_data_api_not_upstream(self):
        with mock.patch.object(ta.jwtcheck, "verify", return_value=ALICE):
            self.assertEqual(ta.handle_call("t", {"name": "read_note", "arguments": {"id": "a1"}}), "text")
        self.upstream.assert_called_once()

    def test_data_api_error_is_an_error(self):
        self.http.return_value = (401, {"message": "no"})
        with self.assertRaises(RuntimeError):
            ta.read_note("alice", {"id": "a1"})

    def test_published_definition_is_the_adapters_own(self):
        self.assertEqual(list(ta.OPERATIONS), ["read_note"])
        self.assertEqual(ta.OPERATIONS["read_note"][0]["inputSchema"]["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
