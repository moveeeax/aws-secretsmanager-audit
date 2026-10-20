"""CLI tests: exit codes, both renderers, and the offline replay guarantee."""

import io
import json
import sys

from aws_secretsmanager_audit.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, main


def run(args):
    out, err = io.StringIO(), io.StringIO()
    code = main(args, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_a_clean_account_exits_zero(fixture_path):
    code, out, _ = run(["--from-json", str(fixture_path("empty.json"))])
    assert code == EXIT_CLEAN
    assert "no findings across 0 secret(s)" in out


def test_fail_on_a_rule_that_fired_exits_one(fixture_path):
    code, _, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--fail-on", "rotation-stale",
    ])
    assert code == EXIT_FINDINGS


def test_fail_on_a_rule_that_did_not_fire_exits_zero(fixture_path):
    code, _, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--fail-on", "pending-deletion",
    ])
    assert code == EXIT_CLEAN


def test_an_unknown_rule_name_exits_two(fixture_path):
    code, _, err = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--fail-on", "rotation-stale,rotation-slightly-late",
    ])
    assert code == EXIT_USAGE
    assert "rotation-slightly-late" in err
    assert "known rules:" in err


def test_an_unknown_ignore_rule_also_exits_two(fixture_path):
    code, _, err = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--ignore-rule", "no-such-rule",
    ])
    assert code == EXIT_USAGE
    assert "no-such-rule" in err


def test_a_missing_payload_file_exits_two():
    code, _, err = run(["--from-json", "/nonexistent/secrets.json"])
    assert code == EXIT_USAGE
    assert "cannot read payload" in err


def test_from_json_rejects_profile_because_it_never_calls_aws(fixture_path):
    code, _, err = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--profile", "prod",
    ])
    assert code == EXIT_USAGE
    assert "do not apply" in err


def test_json_output_is_valid_and_carries_the_summary(fixture_path):
    code, out, _ = run([
        "--from-json", str(fixture_path("hygiene.json")),
        "--format", "json",
    ])
    assert code == EXIT_CLEAN
    doc = json.loads(out)
    assert doc["account"] == "111122223333"
    assert doc["audited"] == 5
    assert doc["summary"]["total"] == len(doc["findings"])
    assert doc["summary"]["by_rule"]["default-kms-key"] == 1
    assert doc["as_of"] == "2026-10-20T12:00:00+00:00"


def test_text_output_groups_by_secret(fixture_path):
    _, out, _ = run(["--from-json", str(fixture_path("hygiene.json"))])
    assert out.splitlines()[0] == "legacy/import-key"
    assert "  high   rotation-disabled" in out
    assert "finding(s) across 4 of 5 secret(s)" in out


def test_replay_is_byte_for_byte_stable(fixture_path):
    """The dump carries collected_at, so ages do not drift with the wall clock."""
    first = run(["--from-json", str(fixture_path("hygiene.json")), "--format", "json"])
    second = run(["--from-json", str(fixture_path("hygiene.json")), "--format", "json"])
    assert first == second
    assert "boto3" not in sys.modules


def test_as_of_overrides_the_payload_timestamp(fixture_path):
    _, out, _ = run([
        "--from-json", str(fixture_path("hygiene.json")),
        "--as-of", "2026-11-05T12:00:00Z",
        "--format", "json",
    ])
    doc = json.loads(out)
    pending = [f for f in doc["findings"] if f["rule"] == "pending-deletion"]
    assert any("recovery window closed" in f["detail"] for f in pending)


def test_a_bad_as_of_exits_two(fixture_path):
    code, _, err = run([
        "--from-json", str(fixture_path("hygiene.json")),
        "--as-of", "last tuesday",
    ])
    assert code == EXIT_USAGE
    assert "cannot read --as-of" in err


def test_dump_json_round_trips_through_the_rules(fixture_path, tmp_path):
    dump = tmp_path / "dump.json"
    _, direct, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--format", "json",
    ])
    run([
        "--from-json", str(fixture_path("rotation.json")),
        "--dump-json", str(dump),
    ])
    _, replayed, _ = run(["--from-json", str(dump), "--format", "json"])
    assert json.loads(direct)["findings"] == json.loads(replayed)["findings"]


def test_unused_days_is_tunable(fixture_path):
    _, strict, _ = run([
        "--from-json", str(fixture_path("hygiene.json")),
        "--unused-days", "365", "--format", "json",
    ])
    assert not [f for f in json.loads(strict)["findings"] if f["rule"] == "unused-secret"]


def test_ignore_secret_is_honoured_from_the_cli(fixture_path):
    _, out, _ = run([
        "--from-json", str(fixture_path("hygiene.json")),
        "--ignore-secret", "legacy/import-key", "--format", "json",
    ])
    assert all(f["secret"] != "legacy/import-key" for f in json.loads(out)["findings"])


def test_severity_filter_is_honoured_from_the_cli(fixture_path):
    _, out, _ = run([
        "--from-json", str(fixture_path("hygiene.json")),
        "--severity", "medium", "--format", "json",
    ])
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"high", "medium"}
