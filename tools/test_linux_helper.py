"""The private binary IPC must refuse oversized/truncated requests headlessly."""
import importlib.util
import io
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "linux_helper", Path(__file__).resolve().parents[1] / "kw-platform/src/linux_helper.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class LinuxHelperTests(unittest.TestCase):
    def read(self, data):
        class Input:
            buffer = io.BytesIO(data)
        with patch.object(helper.sys, "stdin", Input()):
            return helper.receive()

    def test_truncated_request_fails_without_dispatch(self):
        for data in (b"", b"\x00\x00", struct.pack(">I", 10) + b"{}"):
            with self.subTest(data=data), self.assertRaises(EOFError):
                self.read(data)

    def test_oversized_header_is_rejected_before_allocating_it(self):
        with self.assertRaisesRegex(ValueError, "header-too-large"):
            self.read(struct.pack(">I", helper.MAX_HEADER + 1))

    def test_payload_bounds_are_enforced_before_reading(self):
        for count in (-1, helper.MAX_PAYLOAD + 1, "not-an-integer"):
            header = json.dumps({"op": "frame", "bytes": count}).encode()
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "payload-too-large"):
                self.read(struct.pack(">I", len(header)) + header)

    def test_binary_payload_does_not_become_control_json(self):
        body = b'{"op":"shell"}\x00\xff'
        header = json.dumps({"op": "encode", "bytes": len(body)}).encode()
        request, payload = self.read(struct.pack(">I", len(header)) + header + body)
        self.assertEqual(request["op"], "encode")
        self.assertEqual(payload, body)

    def test_no_arbitrary_process_operation(self):
        backend = helper.Backend.__new__(helper.Backend)
        backend.role = "inventory"
        with self.assertRaisesRegex(ValueError, "unsupported-operation"):
            backend.dispatch({"op": "shell", "argv": ["sh"]}, b"")


if __name__ == "__main__":
    unittest.main()
