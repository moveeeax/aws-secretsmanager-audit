"""The rotation schedule and its iCalendar export. No AWS, only fixtures."""

import datetime as dt
import io
import json

import pytest

from aws_secretsmanager_audit.cli import EXIT_CLEAN, EXIT_USAGE, main
from aws_secretsmanager_audit.rules import Options
from aws_secretsmanager_audit.schedule import build_schedule, parse_duration, parse_intervals

from .conftest import AS_OF


def run(args):
    out, err = io.StringIO(), io.StringIO()
    code = main(args, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def schedule_for(payload):
    def _run(name, as_of=AS_OF, intervals=(), remind_days=14, **kwargs):
        rows = build_schedule(payload(name), as_of, Options(**kwargs), intervals, remind_days)
        return {r.secret: r for r in rows}, rows

    return _run


@pytest.mark.parametrize("text,days", [("90", 90), ("90d", 90), ("13w", 91), (" 7D ", 7), ("0d", 0)])
def test_parse_duration_reads_days_and_weeks(text, days):
    assert parse_duration(text) == days


@pytest.mark.parametrize("text", ["", "90 days", "-1d", "3m", "1.5d"])
def test_parse_duration_rejects_anything_else(text):
    with pytest.raises(ValueError):
        parse_duration(text)


def test_parse_intervals_splits_commas_and_keeps_order():
    assert parse_intervals(["db|password=90d,signing=365d", "default=26w"]) == [
        ("db|password", 90),
        ("signing", 365),
        ("default", 182),
    ]


@pytest.mark.parametrize("value", ["90d", "=90d", "db=0d", "db(=90d", "db=soon"])
def test_parse_intervals_rejects_malformed_items(value):
    with pytest.raises(ValueError):
        parse_intervals([value])


def test_the_configured_interval_sets_the_due_date(schedule_for):
    rows, _ = schedule_for("rotation.json")
    stale = rows["prod/api/stale-token"]
    assert stale.interval_days == 30
    assert stale.interval_source == "rotation rules"
    assert stale.basis == "last rotated"
    assert stale.due == dt.date(2026, 8, 16)
    assert stale.days_left == -65
    assert stale.status == "overdue"
    assert stale.owner == "payments"


def test_a_rate_expression_schedules_like_a_day_count(schedule_for):
    rows, _ = schedule_for("rotation.json")
    assert rows["prod/api/rate-token"].interval_days == 14
    assert rows["prod/api/rate-token"].due == dt.date(2026, 7, 31)


def test_a_recent_rotation_is_ok_until_the_reminder_window(schedule_for):
    rows, _ = schedule_for("rotation.json")
    assert rows["prod/db/rotating-password"].status == "ok"
    assert rows["prod/db/rotating-password"].days_left == 19
    rows, _ = schedule_for("rotation.json", remind_days=20)
    assert rows["prod/db/rotating-password"].status == "due-soon"


def test_past_the_due_date_but_inside_the_grace_is_due_not_overdue(schedule_for):
    # stale-token fell due on 2026-08-16; four days later it is late but inside the 7d grace.
    rows, _ = schedule_for("rotation.json", as_of=dt.datetime(2026, 8, 20, 12, tzinfo=dt.timezone.utc))
    assert rows["prod/api/stale-token"].status == "due"
    assert rows["prod/api/stale-token"].days_left == -4


def test_overdue_agrees_with_rotation_stale(schedule_for, rules_for):
    rows, _ = schedule_for("rotation.json")
    fired = rules_for("rotation.json")
    overdue = {name for name, r in rows.items() if r.status == "overdue" and r.basis == "last rotated"}
    stale = {name for name, rules in fired.items() if "rotation-stale" in rules}
    assert overdue == stale


def test_a_never_rotated_secret_counts_from_creation(schedule_for):
    rows, _ = schedule_for("rotation.json")
    configured = rows["prod/api/configured-token"]
    assert configured.basis == "created, never rotated"
    assert configured.due == dt.date(2024, 5, 31)
    assert configured.status == "overdue"


def test_no_interval_means_unscheduled_and_sorted_last(schedule_for):
    rows, ordered = schedule_for("rotation.json")
    assert rows["prod/api/cron-token"].status == "unscheduled"
    assert rows["prod/db/master-password"].status == "unscheduled"
    assert [r.status for r in ordered[-2:]] == ["unscheduled", "unscheduled"]
    dues = [r.due for r in ordered if r.due]
    assert dues == sorted(dues)


def test_an_interval_policy_schedules_a_secret_with_rotation_off(schedule_for):
    rows, _ = schedule_for("rotation.json", intervals=[("master", 90)])
    master = rows["prod/db/master-password"]
    assert master.interval_days == 90
    assert master.interval_source == "--interval master"
    assert master.due == dt.date(2023, 5, 15)


def test_a_stricter_policy_overrides_the_configured_interval(schedule_for):
    rows, _ = schedule_for("rotation.json", intervals=[("yearly", 90)])
    yearly = rows["prod/api/yearly-token"]
    assert (yearly.interval_days, yearly.interval_source) == (90, "--interval yearly")


def test_a_looser_policy_does_not_relax_the_configured_interval(schedule_for):
    rows, _ = schedule_for("rotation.json", intervals=[("default", 180)])
    assert rows["prod/api/stale-token"].interval_days == 30
    assert rows["prod/api/stale-token"].interval_source == "rotation rules"
    # ...but the default does schedule the cron secret and the one with rotation off.
    assert rows["prod/api/cron-token"].interval_source == "--interval default"


def test_the_first_matching_pattern_wins_over_default(schedule_for):
    rows, _ = schedule_for("rotation.json", intervals=[("default", 30), ("password", 365)])
    assert rows["prod/db/master-password"].interval_source == "--interval password"


def test_deleted_ignored_and_non_credential_secrets_are_left_off(schedule_for):
    rows, _ = schedule_for("hygiene.json", ignore_secrets=["legacy/*"])
    assert set(rows) == {"ops/fresh-secret"}
    rows, _ = schedule_for("hygiene.json", all_secrets=True)
    assert "ops/kubeconfig-blob" in rows
    assert "ops/pending-delete" not in rows


def test_schedule_json_carries_every_row_and_a_status_summary(fixture_path):
    code, out, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--schedule", "--format", "json",
    ])
    assert code == EXIT_CLEAN
    doc = json.loads(out)
    assert doc["remind_before_days"] == 14
    assert doc["rotation_grace_days"] == 7
    assert len(doc["schedule"]) == 7
    assert doc["summary"]["by_status"] == {
        "overdue": 3, "due": 0, "due-soon": 0, "ok": 2, "unscheduled": 2,
    }
    first = doc["schedule"][0]
    assert first["secret"] == "prod/api/configured-token"
    assert first["due"] == "2024-05-31"
    assert first["owner"] == "partners"


def test_schedule_text_names_due_date_status_and_owner(fixture_path):
    _, out, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--schedule", "--remind-before", "3w",
    ])
    first = out.splitlines()[0].split()
    assert first == ["2024-05-31", "872d", "late", "overdue", "partners", "prod/api/configured-token"]
    assert "reminding 21d ahead" in out
    assert "due-soon=1" in out


def test_schedule_text_groups_by_owner(fixture_path):
    _, out, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--schedule", "--group-by", "owner",
    ])
    lines = out.splitlines()
    assert lines[0] == "partners"
    assert lines[1].split()[-1] == "prod/api/configured-token"


def test_schedule_and_fail_on_together_exit_two(fixture_path):
    code, _, err = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--schedule", "--fail-on", "rotation-stale",
    ])
    assert code == EXIT_USAGE
    assert "--schedule" in err


@pytest.mark.parametrize("flag", [["--interval", "db=forever"], ["--remind-before", "soon"]])
def test_bad_schedule_options_exit_two(fixture_path, flag):
    code, _, err = run(["--from-json", str(fixture_path("rotation.json")), "--schedule"] + flag)
    assert code == EXIT_USAGE
    assert "cannot read the schedule options" in err


def test_export_ics_writes_one_event_per_due_date(fixture_path, tmp_path):
    ics = tmp_path / "rotation.ics"
    code, out, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--owners", str(fixture_path("owners.yaml")),
        "--export-ics", str(ics),
    ])
    # Without --schedule the findings report still goes to stdout.
    assert code == EXIT_CLEAN
    assert "rotation-stale" in out
    body = ics.read_bytes().decode("utf-8")
    assert body.startswith("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n")
    assert body.endswith("END:VCALENDAR\r\n")
    assert body.count("BEGIN:VEVENT") == 5
    assert "DTSTART;VALUE=DATE:20260816\r\n" in body
    assert "SUMMARY:Rotate prod/api/stale-token (65d late)\r\n" in body
    assert "TRIGGER:-P14D\r\n" in body
    unfolded = body.replace("\r\n ", "")
    assert 'ATTENDEE;CN="oncall-payments@example.com":mailto:oncall-payments@example.com' in unfolded
    assert all(len(line.encode("utf-8")) <= 75 for line in body.split("\r\n"))


def test_export_ics_is_stable_across_replays(fixture_path, tmp_path):
    first, second = tmp_path / "a.ics", tmp_path / "b.ics"
    for path in (first, second):
        run(["--from-json", str(fixture_path("rotation.json")), "--schedule", "--export-ics", str(path)])
    assert first.read_bytes() == second.read_bytes()


def test_ics_text_is_escaped_and_folded(fixture_path, tmp_path):
    ics = tmp_path / "rotation.ics"
    run(["--from-json", str(fixture_path("rotation.json")), "--schedule", "--export-ics", str(ics)])
    body = ics.read_bytes().decode("utf-8")
    unfolded = body.replace("\r\n ", "")
    assert (
        "DESCRIPTION:owner: payments\\ninterval: 30d from rotation rules\\nlast rotated: 2026-07-17"
        in unfolded
    )
    assert "created\\, never rotated" in unfolded
