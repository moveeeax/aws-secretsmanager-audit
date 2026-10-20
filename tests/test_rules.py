"""Rule-level tests. None of these import boto3 or touch the network."""

import datetime as dt

import pytest

from aws_secretsmanager_audit.model import Payload, parse_time
from aws_secretsmanager_audit.rules import ALL_RULES, Options, audit

from .conftest import AS_OF


def test_rotation_disabled_fires_and_a_recent_rotation_does_not(rules_for):
    fired = rules_for("rotation.json")
    assert fired["prod/db/master-password"] == {"rotation-disabled"}
    assert "prod/db/rotating-password" not in fired


def test_rotation_stale_names_the_interval_and_the_age(findings_for):
    stale = [
        f
        for f in findings_for("rotation.json")
        if f.secret == "prod/api/stale-token"
    ]
    assert [f.rule for f in stale] == ["rotation-stale"]
    detail = stale[0].detail
    assert "every 30d" in detail
    assert "95d ago" in detail
    assert "2026-07-17" in detail


def test_a_long_interval_is_not_stale_at_the_same_age(rules_for):
    fired = rules_for("rotation.json")
    assert "prod/api/yearly-token" not in fired


def test_never_rotated_and_rotation_stale_never_both_fire(rules_for):
    fired = rules_for("rotation.json")
    assert fired["prod/api/configured-token"] == {"never-rotated"}


def test_a_cron_schedule_is_not_guessed_at(rules_for):
    """No AutomaticallyAfterDays and no rate() means no defensible staleness claim."""
    fired = rules_for("rotation.json")
    assert "prod/api/cron-token" not in fired


def test_a_rate_expression_is_read_as_an_interval(findings_for):
    rate = [f for f in findings_for("rotation.json") if f.secret == "prod/api/rate-token"]
    assert [f.rule for f in rate] == ["rotation-stale"]
    assert "every 14d" in rate[0].detail


def test_rotation_grace_absorbs_a_small_overrun(rules_for):
    # stale-token is 95 days into a 30 day cycle; a 70 day grace covers it.
    fired = rules_for("rotation.json", rotation_grace_days=70)
    assert "prod/api/stale-token" not in fired


def test_wildcard_principal_fires_but_an_org_condition_does_not(rules_for):
    fired = rules_for("policies.json")
    assert fired["shared/wildcard"] == {"wildcard-resource-policy"}
    assert "shared/org-scoped" not in fired


def test_cross_account_principal_fires_and_same_account_does_not(rules_for):
    fired = rules_for("policies.json")
    assert fired["shared/cross-account"] == {"wildcard-resource-policy"}
    assert "shared/same-account" not in fired


def test_a_deny_statement_is_not_a_hole(rules_for):
    fired = rules_for("policies.json")
    assert "shared/denied-wildcard" not in fired


def test_a_neglected_secret_collects_every_hygiene_rule(rules_for):
    fired = rules_for("hygiene.json")
    assert fired["legacy/import-key"] == {
        "rotation-disabled",
        "unused-secret",
        "default-kms-key",
        "no-description",
        "untagged",
    }


def test_unused_detail_reports_the_age_and_threshold(findings_for):
    unused = [
        f
        for f in findings_for("hygiene.json")
        if f.secret == "legacy/import-key" and f.rule == "unused-secret"
    ]
    assert "200d ago" in unused[0].detail
    assert "threshold 90d" in unused[0].detail


def test_a_secret_younger_than_the_window_is_not_called_unused(rules_for):
    fired = rules_for("hygiene.json")
    assert fired["ops/fresh-secret"] == {"rotation-disabled"}


def test_a_secret_pending_deletion_reports_the_remaining_window(findings_for):
    pending = [f for f in findings_for("hygiene.json") if f.secret == "ops/pending-delete"]
    assert [f.rule for f in pending] == ["pending-deletion"]
    assert "12d of recovery window left" in pending[0].detail


def test_a_closed_recovery_window_says_so(findings_for):
    expired = [f for f in findings_for("hygiene.json") if f.secret == "ops/expired-recovery"]
    assert [f.rule for f in expired] == ["pending-deletion"]
    assert "recovery window closed" in expired[0].detail


def test_a_secret_that_is_not_credential_shaped_skips_rotation_rules(rules_for):
    fired = rules_for("hygiene.json")
    assert "ops/kubeconfig-blob" not in fired


def test_all_secrets_overrides_the_heuristic(rules_for):
    fired = rules_for("hygiene.json", all_secrets=True)
    assert fired["ops/kubeconfig-blob"] == {"rotation-disabled"}


def test_require_tags_replaces_the_bare_untagged_check(findings_for):
    tagged = {
        f.secret
        for f in findings_for("hygiene.json", require_tags=["CostCentre"])
        if f.rule == "untagged"
    }
    # Everything live is missing CostCentre; the deleted secrets are left alone.
    assert tagged == {"legacy/import-key", "ops/fresh-secret", "ops/kubeconfig-blob"}


def test_ignore_rule_suppresses_only_its_target(rules_for):
    fired = rules_for("hygiene.json", ignore_rules=["unused-secret"])
    assert fired["legacy/import-key"] == {
        "rotation-disabled",
        "default-kms-key",
        "no-description",
        "untagged",
    }


def test_ignore_secret_suppresses_only_its_target(rules_for):
    fired = rules_for("hygiene.json", ignore_secrets=["legacy/import-key"])
    assert "legacy/import-key" not in fired
    assert "ops/pending-delete" in fired


def test_ignore_secret_accepts_a_prefix_glob(rules_for):
    fired = rules_for("hygiene.json", ignore_secrets=["ops/*"])
    assert set(fired) == {"legacy/import-key"}


def test_severity_filter_drops_the_low_noise(findings_for):
    severities = {f.severity for f in findings_for("hygiene.json", min_severity="high")}
    assert severities == {"high"}


def test_findings_are_sorted_by_secret_then_severity(findings_for):
    findings = findings_for("hygiene.json")
    names = [f.secret for f in findings]
    assert names == sorted(names)
    first = [f for f in findings if f.secret == "legacy/import-key"]
    assert [f.severity for f in first] == ["high", "medium", "low", "low", "low"]


def test_every_rule_has_a_declared_severity():
    from aws_secretsmanager_audit.rules import RULE_SEVERITY

    assert set(ALL_RULES) == set(RULE_SEVERITY)


def test_an_empty_account_produces_no_findings(payload):
    assert audit(payload("empty.json"), AS_OF, Options()) == []


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-17T12:00:00Z",
        "2026-07-17T12:00:00+00:00",
        "2026-07-17 12:00:00+00:00",
        dt.datetime(2026, 7, 17, 12, 0, 0),
    ],
)
def test_parse_time_accepts_every_shape_aws_and_json_produce(value):
    assert parse_time(value) == dt.datetime(2026, 7, 17, 12, 0, 0, tzinfo=dt.timezone.utc)


def test_parse_time_passes_none_through():
    assert parse_time(None) is None
    assert parse_time("") is None


def test_a_string_resource_policy_is_parsed_like_a_dict():
    raw = {
        "secrets": [
            {
                "ARN": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:x-a1",
                "Name": "x",
                "Description": "d",
                "KmsKeyId": "arn:aws:kms:eu-west-1:111122223333:key/abc",
                "Tags": [{"Key": "Owner", "Value": "o"}],
                "LastAccessedDate": "2026-10-19T00:00:00Z",
                "ResourcePolicy": '{"Statement":[{"Effect":"Allow","Principal":"*"}]}',
            }
        ]
    }
    rules = {f.rule for f in audit(Payload(raw), AS_OF, Options())}
    assert "wildcard-resource-policy" in rules
