"""Unit tests for the fixture validator's rejection rules."""
import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import validate_fixtures

VECTORS = Path(__file__).resolve().parent.parent / "protocol" / "v1" / "vectors"


def load(name):
    return json.loads((VECTORS / f"{name}.json").read_text())


class ValidatorTests(unittest.TestCase):
    def test_valid_tree_passes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(validate_fixtures.main(), 0)

    def test_wrong_protocol_rejected(self):
        message = copy.deepcopy(load("hello"))
        message["protocol"] = "selkies"
        self.assertFalse(validate_fixtures.check_envelope("hello", message))

    def test_stale_resize_ack_rejected(self):
        ack = copy.deepcopy(load("resize-ack"))
        ack["payload"]["requestId"] = "00000000-0000-4000-8000-000000000000"
        request = load("resize-request")["payload"]
        self.assertNotEqual(ack["payload"]["requestId"], request["requestId"])

    def test_negative_sequence_rejected(self):
        message = copy.deepcopy(load("keyframe"))
        message["sequence"] = -1
        self.assertFalse(validate_fixtures.check_envelope("keyframe", message))

    def test_out_of_range_input_rejected(self):
        payload = {"kind": "wheel", "dx": 0, "dy": validate_fixtures.INPUT_MAX_WHEEL + 1}
        self.assertFalse(validate_fixtures.check_input("input-wheel", payload))
        keysym = {"kind": "key", "keysym": validate_fixtures.INPUT_MAX_KEYSYM + 1, "down": True}
        self.assertFalse(validate_fixtures.check_input("input", keysym))

    def test_unknown_input_kind_rejected(self):
        self.assertFalse(validate_fixtures.check_input("input", {"kind": "macro"}))


if __name__ == "__main__":
    unittest.main()
