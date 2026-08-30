import unittest

from human_codex.core_ipc import Envelope, IpcValidationError, MAX_FRAME_BYTES, MAX_METHOD_CHARS, encode, decode, request


class CoreIpcTests(unittest.TestCase):
    def test_request_round_trip(self) -> None:
        message = request("system.health", {})
        recovered = decode(encode(message))
        self.assertEqual(recovered.protocol, "hc-ipc/1")
        self.assertEqual(recovered.method, "system.health")
        self.assertEqual(recovered.id, recovered.correlation_id)

    def test_malformed_json_and_extra_field_are_rejected(self) -> None:
        with self.assertRaises(IpcValidationError):
            decode("{")
        with self.assertRaises(IpcValidationError):
            decode('{"protocol":"hc-ipc/1","kind":"request","id":"msg_123","correlation_id":"msg_123","method":"system.health","params":{},"timestamp":"now","command":"no"}')

    def test_oversized_method_and_timestamp_are_rejected(self) -> None:
        with self.assertRaises(IpcValidationError):
            decode('{"protocol":"hc-ipc/1","kind":"request","id":"msg_123","correlation_id":"msg_123","method":"' + "x" * (MAX_METHOD_CHARS + 1) + '","params":{},"timestamp":"now"}')
        with self.assertRaises(IpcValidationError):
            decode('{"protocol":"hc-ipc/1","kind":"request","id":"msg_123","correlation_id":"msg_123","method":"system.health","params":{},"timestamp":"' + "x" * 65 + '"}')

    def test_oversized_encoded_frame_is_rejected(self) -> None:
        message = Envelope("hc-ipc/1", "request", "msg_123", "msg_123", "system.health", {"padding": "x" * MAX_FRAME_BYTES}, "now")
        with self.assertRaises(IpcValidationError):
            encode(message)


if __name__ == "__main__":
    unittest.main()
