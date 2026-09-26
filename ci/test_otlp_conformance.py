import concurrent.futures
import socket
import struct
import unittest

from otlp_conformance import ready


class Readiness(unittest.TestCase):
    def test_starting_service_connection_reset_is_not_ready(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)

            def reset_peer():
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(5)
                    peer.recv(4096)
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                reset = worker.submit(reset_peer)
                self.assertFalse(ready(f"http://127.0.0.1:{listener.getsockname()[1]}/healthz"))
                reset.result(timeout=5)
