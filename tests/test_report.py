import json

import pytest

from vps_secure_init.report import acceptance_check, build_acceptance_report, write_acceptance_reports


def test_acceptance_reports_are_masked_dual_format_and_non_secret(tmp_path):
    report = build_acceptance_report(
        "hk-01", "203.0.113.10",
        [
            acceptance_check("ssh.password_authentication", "critical", "no", "no", True, "sshd -T"),
            acceptance_check("fail2ban.sshd", "high", "active", "inactive", False, "service inactive"),
        ],
        plan={"plan_id": "plan-1", "plan_sha256": "abc", "payload_sha256": {"finalize.sh": "def"}},
    )
    paths = write_acceptance_reports(tmp_path, report)

    assert report["overall_status"] == "FAIL"
    assert report["host"]["address"] == "203.0.***.***"
    assert set(paths) == {"json", "markdown"}
    assert all(path.exists() and path.stat().st_mode & 0o777 == 0o600 for path in paths.values())
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["summary"]["failed"] == 1
    assert "最终验收报告" in paths["markdown"].read_text(encoding="utf-8")


def test_report_rejects_secret_bearing_check_data():
    with pytest.raises(ValueError, match="敏感字段"):
        build_acceptance_report(
            "hk-01", "203.0.113.10",
            [{"id": "x", "severity": "critical", "expected": "x", "actual": "x", "status": "PASS",
              "evidence": "x", "managed_password": "secret"}],
        )


def test_report_formats_are_taken_from_frozen_plan_settings(tmp_path):
    report = build_acceptance_report(
        "hk-01", "203.0.113.10",
        [acceptance_check("x", "low", "yes", "yes", True, "evidence")],
        plan={"plan_id": "plan-1", "plan_sha256": "abc", "report_settings": {"formats": ["json"], "address_display": "masked"}},
    )
    paths = write_acceptance_reports(tmp_path, report)
    assert set(paths) == {"json"}
