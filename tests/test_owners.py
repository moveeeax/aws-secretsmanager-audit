"""Owner resolution and the unowned-secret rule. No AWS, only fixtures."""

import io
import json

import pytest

from aws_secretsmanager_audit.cli import EXIT_CLEAN, EXIT_USAGE, main
from aws_secretsmanager_audit.model import Secret
from aws_secretsmanager_audit.owners import OwnersError, load_owners, resolve_owner


def run(args):
    out, err = io.StringIO(), io.StringIO()
    code = main(args, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def secret(name, tags=(), arn=""):
    return Secret({"Name": name, "ARN": arn, "Tags": [{"Key": k, "Value": v} for k, v in tags]})


def test_the_owners_file_keeps_its_order(fixture_path):
    rules = load_owners(str(fixture_path("owners.yaml")))
    assert [p for p, _ in rules] == ["prod/api/stale-token", "prod/api/*", "legacy/*"]


def test_the_first_matching_glob_wins(fixture_path):
    rules = load_owners(str(fixture_path("owners.yaml")))
    assert resolve_owner(secret("prod/api/stale-token"), rules, "owner") == "oncall-payments@example.com"
    assert resolve_owner(secret("prod/api/yearly-token"), rules, "owner") == "api-team"


def test_the_file_beats_the_tag_and_the_tag_is_the_fallback(fixture_path):
    rules = load_owners(str(fixture_path("owners.yaml")))
    tagged = [("Owner", "platform")]
    assert resolve_owner(secret("prod/api/x", tagged), rules, "owner") == "api-team"
    assert resolve_owner(secret("prod/db/x", tagged), rules, "owner") == "platform"


def test_an_exact_arn_is_accepted_as_a_key():
    arn = "arn:aws:secretsmanager:eu-west-1:111122223333:secret:prod/x-a1b2c3"
    assert resolve_owner(secret("prod/x", arn=arn), [(arn, "team-x")], "owner") == "team-x"


def test_the_tag_key_is_matched_case_insensitively_when_not_exact():
    assert resolve_owner(secret("a", [("OWNER", "ops")]), (), "owner") == "ops"
    both = secret("a", [("Owner", "loose"), ("owner", "exact")])
    assert resolve_owner(both, (), "owner") == "exact"


def test_an_empty_tag_value_is_not_an_owner():
    assert resolve_owner(secret("a", [("owner", "  ")]), (), "owner") is None


def test_an_empty_owner_tag_turns_the_lookup_off():
    assert resolve_owner(secret("a", [("owner", "ops")]), (), "") is None


@pytest.mark.parametrize(
    "body",
    ["- prod/*: team\n", "prod/*:\n", "prod/*: [a, b]\n", "prod/*: {team: a}\n", "prod/*: 'x\n"],
)
def test_a_malformed_owners_file_is_rejected(tmp_path, body):
    path = tmp_path / "owners.yaml"
    path.write_text(body)
    with pytest.raises(OwnersError):
        load_owners(str(path))


def test_an_empty_owners_file_means_no_rules(tmp_path):
    path = tmp_path / "owners.yaml"
    path.write_text("# nothing yet\n")
    assert load_owners(str(path)) == []


def test_unowned_secret_fires_only_where_nobody_owns_it(rules_for):
    fired = rules_for("hygiene.json")
    unowned = {name for name, rules in fired.items() if "unowned-secret" in rules}
    # The other live secrets carry an Owner tag; the deleted ones are left alone.
    assert unowned == {"legacy/import-key"}


def test_the_owners_file_clears_unowned_secret(fixture_path, rules_for):
    rules = load_owners(str(fixture_path("owners.yaml")))
    fired = rules_for("hygiene.json", owners=rules)
    assert all("unowned-secret" not in r for r in fired.values())


def test_unowned_detail_names_the_sources_it_tried(findings_for, fixture_path):
    detail = [f.detail for f in findings_for("hygiene.json") if f.rule == "unowned-secret"][0]
    assert detail == "no owner to route findings to: no 'owner' tag"
    without_tag = findings_for("hygiene.json", owner_tag="")
    assert {f.secret for f in without_tag if f.rule == "unowned-secret"} == {
        "legacy/import-key",
        "ops/fresh-secret",
        "ops/kubeconfig-blob",
    }


def test_every_finding_carries_its_owner(findings_for):
    owners = {(f.secret, f.owner) for f in findings_for("rotation.json")}
    assert ("prod/api/stale-token", "payments") in owners
    assert all(owner for _, owner in owners)


def test_json_findings_carry_the_owner_field(fixture_path):
    _, out, _ = run([
        "--from-json", str(fixture_path("rotation.json")),
        "--owners", str(fixture_path("owners.yaml")),
        "--format", "json",
    ])
    by_secret = {f["secret"]: f["owner"] for f in json.loads(out)["findings"]}
    assert by_secret["prod/api/stale-token"] == "oncall-payments@example.com"
    assert by_secret["prod/api/rate-token"] == "api-team"
    assert by_secret["prod/db/master-password"] == "platform"


def test_an_unowned_finding_has_a_null_owner_in_json(fixture_path):
    _, out, _ = run(["--from-json", str(fixture_path("hygiene.json")), "--format", "json"])
    legacy = [f for f in json.loads(out)["findings"] if f["secret"] == "legacy/import-key"]
    assert legacy and all(f["owner"] is None for f in legacy)


def test_text_report_shows_the_owner_next_to_the_secret(fixture_path):
    _, out, _ = run(["--from-json", str(fixture_path("rotation.json"))])
    assert "prod/api/stale-token  (owner: payments)" in out.splitlines()


def test_group_by_owner_puts_each_owner_over_their_secrets(fixture_path):
    code, out, _ = run(["--from-json", str(fixture_path("hygiene.json")), "--group-by", "owner"])
    assert code == EXIT_CLEAN
    lines = out.splitlines()
    assert lines[0] == "ops"
    assert lines[1] == "  ops/expired-recovery"
    # Unowned findings come last, under their own heading.
    unowned = lines.index("(unowned)")
    assert lines[unowned + 1] == "  legacy/import-key"
    assert "legacy/import-key" not in "\n".join(lines[:unowned])


def test_a_bad_owners_file_exits_two(tmp_path, fixture_path):
    path = tmp_path / "owners.yaml"
    path.write_text("- not a mapping\n")
    code, _, err = run(["--from-json", str(fixture_path("hygiene.json")), "--owners", str(path)])
    assert code == EXIT_USAGE
    assert "cannot read --owners" in err


def test_a_missing_owners_file_exits_two(fixture_path):
    code, _, err = run([
        "--from-json", str(fixture_path("hygiene.json")),
        "--owners", "/nonexistent/owners.yaml",
    ])
    assert code == EXIT_USAGE
    assert "cannot read --owners" in err


def test_unowned_secret_can_gate_a_pipeline(fixture_path):
    code, _, _ = run(["--from-json", str(fixture_path("hygiene.json")), "--fail-on", "unowned-secret"])
    assert code == 1
