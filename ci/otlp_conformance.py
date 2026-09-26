#!/usr/bin/env python3
import argparse
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid


SUBJECT = "system:serviceaccount:ci:conformance"
BODY = b"conformance upstream\n"


def session_id():
    return str(uuid.UUID(int=(int(time.time() * 1000) << 80) | (7 << 76)
                         | (secrets.randbits(12) << 64) | (2 << 62)
                         | secrets.randbits(62)))


def eventually(description, probe, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {description}")


def request_json(url, payload=None, authorization=None):
    headers = {"Content-Type": "application/json"}
    if authorization:
        headers["Authorization"] = authorization
    request = urllib.request.Request(
        url, data=None if payload is None else json.dumps(payload).encode(), headers=headers
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def ready(url):
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.received.append((self.path, dict(self.headers.items())))
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        pass


def emit(binary, directory, endpoint, protocol, authorization, upstream):
    session = session_id()
    headers = directory / "headers"
    headers.write_text(f"Authorization: {authorization}\n" if authorization else "")
    headers.chmod(0o600)
    config = {
        "listen": "127.0.0.1:0",
        "auth": {"issuers": [], "subjects": []},
        "shapes": {"ci": {"vcpus": 1, "memoryMiB": 128, "diskMiB": 128}},
        "profiles": {"ci": {
            "shape": "ci", "image": "ci@sha256:" + "0" * 64,
            "browser": "headless", "idleSeconds": 60, "maxSeconds": 60,
            "egress": {"allow": ["127.0.0.1"], "allowPrivate": ["127.0.0.0/8"], "dns": "runner"},
        }},
        "quotas": {"default": {"maxSessions": 1}, "subjects": {}},
        "telemetry": {"otlp": {
            "protocol": protocol, "endpoint": endpoint, "headersFile": str(headers),
        }},
    }
    config_path = directory / "config.json"
    config_path.write_text(json.dumps(config))
    env = dict(os.environ, OTEL_RESOURCE_ATTRIBUTES=
               f"vm_runner.session_id={session},vm_runner.subject={SUBJECT}")
    log_path = directory / "egress.log"
    with log_path.open("w") as log:
        process = subprocess.Popen([
            str(binary), "egress", "--config", str(config_path), "--profile", "ci",
            "--listen", "127.0.0.1:0", "--ca-out", str(directory / "ca"),
        ], env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            def listening():
                assert process.poll() is None, f"egress exited; see {log_path}"
                for line in log_path.read_text().split("\n")[:-1]:
                    record = json.loads(line)
                    if record.get("fields", {}).get("message") == "listening":
                        return record["fields"]["addr"]
                return None

            address = eventually("egress listener", listening, seconds=30)
            host, port = address.rsplit(":", 1)
            url = f"http://127.0.0.1:{upstream.server_port}/{session}"
            connection = http.client.HTTPConnection(host, int(port), timeout=20)
            try:
                connection.request("GET", url, headers={
                    "Connection": "close",
                    "traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01",
                    "tracestate": "ci=must-be-stripped",
                })
                response = connection.getresponse()
                assert response.status == 200, f"proxy returned {response.status}"
                assert response.read() == BODY, "loopback upstream body differs"
            finally:
                connection.close()
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=30) == 0, "egress shutdown failed"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            headers.unlink()
    path, forwarded = upstream.received[-1]
    assert path == f"/{session}"
    assert not {"traceparent", "tracestate"} & {key.lower() for key in forwarded}
    return session, url


def search(backend, base, authorization, started, field, value):
    if backend == "quickwit":
        query = f'span_name:"egress.request" AND {field}:"{value}"'
        result = request_json(base + "/api/v1/otel-traces-v0_7/search?" +
                              urllib.parse.urlencode({"query": query, "max_hits": 10}))
        assert not result.get("errors"), result.get("errors")
    else:
        result = request_json(base + "/api/default/_search?type=traces", {
            "query": {
                "sql": 'SELECT * FROM "default" WHERE operation_name = \'egress.request\' '
                       f'AND "{field}" = \'{value}\'',
                "start_time": started, "end_time": time.time_ns() // 1000,
                "from": 0, "size": 10,
            },
        }, authorization)
        assert not result.get("is_partial"), "OpenObserve returned partial results"
    return result["hits"]


def verify(backend, base, authorization, started, session, url):
    session_field = ("resource_attributes.vm_runner.session_id" if backend == "quickwit"
                     else "service_vm_runner_session_id")
    hits = eventually(f"{backend} indexed session", lambda: search(
        backend, base, authorization, started, session_field, session
    ))
    assert len(hits) == 1, f"expected one egress.request, got {len(hits)}"
    span = hits[0]
    with Path("Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["package"]["version"]
    expected_resource = {
        "service.name": "vm-runner", "service.version": version,
        "vm_runner.role": "jail", "vm_runner.session_id": session,
        "vm_runner.subject": SUBJECT, "vm_runner.profile": "ci", "vm_runner.shape": "ci",
        "dekopon.source": "runner",
    }
    expected_span = {
        "http.request.method": "GET", "url.full": url,
        "http.response.status_code": 200, "server.address": "127.0.0.1",
        "egress.decision": "allowed",
    }
    for key, value in expected_resource.items():
        if key == "service.name":
            actual = span.get("service_name")
        elif backend == "quickwit":
            actual = span["resource_attributes"].get(key)
        else:
            actual = span.get("service_" + key.replace(".", "_"))
        assert actual == value, f"{backend}: resource {key}: {actual!r} != {value!r}"
    for key, value in expected_span.items():
        actual = (span["span_attributes"].get(key) if backend == "quickwit"
                  else span.get(key.replace(".", "_")))
        if key == "http.response.status_code":
            actual = int(actual)
        assert actual == value, f"{backend}: span {key}: {actual!r} != {value!r}"
    trace = span["trace_id"]
    assert len(trace) == 32 and int(trace, 16) != 0
    assert trace != "1" * 32, "guest traceparent became the trace parent"
    by_trace = search(backend, base, authorization, started, "trace_id", trace)
    assert [hit["span_id"] for hit in by_trace] == [span["span_id"]]
    for field, missing in [(session_field, session_id()), ("trace_id", "0" * 32)]:
        assert not search(backend, base, authorization, started, field, missing), \
            f"{backend}: {field} predicate did not exclude a missing value"
    evidence = {"backend": backend, "session_id": session, "trace_id": trace,
                "span_id": span["span_id"], "session_filter": session_field,
                "resource": expected_resource, "attributes": expected_span}
    print(json.dumps(evidence), flush=True)
    return evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/debug/vm-runnerd"))
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--openobserve", default="http://127.0.0.1:5080")
    parser.add_argument("--quickwit", default="http://127.0.0.1:7280")
    parser.add_argument("--quickwit-grpc", default="http://127.0.0.1:7281")
    args = parser.parse_args()
    authorization = "Basic " + base64.b64encode(
        (os.environ["ZO_ROOT_USER_EMAIL"] + ":" + os.environ["ZO_ROOT_USER_PASSWORD"]).encode()
    ).decode()
    for backend, url in [
        ("OpenObserve", args.openobserve + "/healthz"),
        ("Quickwit node", args.quickwit + "/health/readyz"),
        ("Quickwit OTLP queue", args.quickwit + "/api/v1/otel-traces-v0_7/tail"),
        ("Quickwit search", args.quickwit + "/api/v1/otel-traces-v0_7/search?query=*"),
    ]:
        eventually(backend + " readiness", lambda: ready(url))
        print(backend + " ready", flush=True)
    with http.server.HTTPServer(("127.0.0.1", 0), Upstream) as upstream:
        upstream.received = []
        thread = threading.Thread(target=upstream.serve_forever)
        thread.start()
        try:
            for backend, base, endpoint, protocol, auth in [
                ("openobserve", args.openobserve, args.openobserve + "/api/default/v1/traces",
                 "http", authorization),
                ("quickwit", args.quickwit, args.quickwit_grpc, "grpc", None),
            ]:
                directory = args.artifacts.resolve() / backend
                directory.mkdir(parents=True, exist_ok=True)
                started = time.time_ns() // 1000
                session, url = emit(args.binary.resolve(), directory, endpoint, protocol,
                                    auth, upstream)
                evidence = verify(backend, base, auth, started, session, url)
                (directory / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        finally:
            upstream.shutdown()
            thread.join()
    print("OTLP CONFORMANCE GREEN: OpenObserve HTTP/protobuf + Quickwit gRPC", flush=True)


if __name__ == "__main__":
    main()
