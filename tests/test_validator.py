from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from vulnproof.models import Asset, Finding
from vulnproof.playbooks import HttpStep, ValidationPlaybook
from vulnproof.validator import HttpValidator


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"VULNPROOF_LAB_MARKER"
        self.send_response(200)
        self.send_header("Set-Cookie", "secret=value")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def test_http_validator_confirms_and_redacts_evidence() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        asset = Asset(
            name="demo",
            environment="lab",
            validation_enabled=True,
            allowed_hosts=["127.0.0.1"],
        )
        finding = Finding(
            vulnerability_id="VP-LAB-0001",
            package_name="demo",
            asset_name="demo",
            source="fixture",
        )
        playbook = ValidationPlaybook(
            id="vp-lab-0001",
            description="test",
            vulnerability_ids=["VP-LAB-0001"],
            steps=[
                HttpStep(
                    name="probe",
                    path="/debug/config",
                    expected_status=200,
                    body_contains="VULNPROOF_LAB_MARKER",
                )
            ],
        )

        result = HttpValidator().run(
            playbook,
            finding,
            asset,
            f"http://127.0.0.1:{server.server_port}",
            approved=True,
        )

        assert result.status == "confirmed"
        assert result.evidence[0].data["response_headers"]["Set-Cookie"] == "[REDACTED]"
    finally:
        server.shutdown()
        server.server_close()
