# aws-secretsmanager-audit

[![ci](https://github.com/moveeeax/aws-secretsmanager-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-secretsmanager-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Secrets Manager is where a credential goes to be forgotten. You create the secret during a
migration, wire it into one task definition, enable rotation "later", and three years on
nobody can tell you whether that database password has ever changed, who can read it, or
whether the rotation Lambda has been failing since its runtime was deprecated.

The console shows a list of names and a green checkmark per secret, which tells you none of
that. This tool answers it: one pass over the account, ten rules, a text table or JSON, an
owner on every finding, a rotation schedule with an iCalendar export, and an exit code you
can gate a pipeline on.

## What it checks

| rule | severity | fires when |
| --- | --- | --- |
| `rotation-disabled` | high | `RotationEnabled` is false on a credential-shaped secret |
| `never-rotated` | high | rotation is enabled and `LastRotatedDate` is absent — configured, never ran |
| `rotation-stale` | high | `LastRotatedDate` is older than the rotation interval plus the grace window |
| `wildcard-resource-policy` | high | an `Allow` statement with `Principal: "*"` or an outside account and no `Condition` |
| `unused-secret` | medium | `LastAccessedDate` older than `--unused-days`, or no recorded access at all |
| `pending-deletion` | medium | `DeletedDate` is set; reports the days left in the recovery window |
| `unowned-secret` | medium | no `--owners` glob matches the name and the secret has no `owner` tag, so nobody gets paged |
| `default-kms-key` | low | no `KmsKeyId`, so the `aws/secretsmanager` managed key encrypts it |
| `no-description` | low | no description, so the secret's purpose is guesswork |
| `untagged` | low | no tags, or missing the keys given by `--require-tags` |

`never-rotated` and `rotation-stale` never both fire on one secret: a secret that has never
rotated has no age to be late by. A secret pending deletion only reports `pending-deletion`,
because telling you to rotate something you just deleted is noise.

## Install

```console
pip install git+https://github.com/moveeeax/aws-secretsmanager-audit
```

Or clone and `pip install -e ".[dev]"` to run the suite.

Collection needs `secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret` and
`secretsmanager:GetResourcePolicy`. It never calls `GetSecretValue`, so the tool never reads
a secret's value — only its metadata.

## Usage

Point it at an account with `--profile`, or run the bundled dump to see the shape of the
report without credentials:

```console
$ aws-secretsmanager-audit --from-json examples/sample-dump.json --severity high
legacy/jenkins-ssh-key
  high   rotation-disabled         rotation is not enabled; value last changed 2020-11-23 (2156d ago)

prod/orders/db-password  (owner: orders)
  high   rotation-stale            rotates every 30d but last rotated 2026-07-17 (95d ago, 58d past the 7d grace)

prod/partner/webhook-secret  (owner: integrations)
  high   rotation-disabled         rotation is not enabled; value last changed 2022-09-10 (1501d ago)
  high   wildcard-resource-policy  statement PartnerMigration2022 allows account 999988887777 (outside 111122223333) with no Condition

prod/stripe/api-key  (owner: payments)
  high   never-rotated             rotation is enabled but has never run; rotation lambda rotate-stripe-key

staging/grafana-admin-password  (owner: sre)
  high   rotation-disabled         rotation is not enabled; value last changed 2025-05-19 (519d ago)

6 finding(s) across 5 of 9 secret(s) — high=6
```

Cache the account once, then iterate on rules offline:

```console
aws-secretsmanager-audit --profile prod --dump-json /tmp/secrets.json
aws-secretsmanager-audit --from-json /tmp/secrets.json --format json \
  | jq '.findings[] | select(.rule=="rotation-stale")'
```

Gate CI on the rules you actually care about:

```console
aws-secretsmanager-audit --fail-on rotation-stale,wildcard-resource-policy \
  --unused-days 180 --ignore-secret 'legacy/*'
```

Exit codes: `0` nothing you asked to fail on fired, `1` something did, `2` the invocation was
wrong (unknown rule name, unreadable payload or `--owners` file, unparseable `--as-of`,
`--interval` or `--remind-before`, or `--fail-on` combined with `--schedule`).

All flags:

| flag | default | what it does |
| --- | --- | --- |
| `--profile NAME` | default credential chain | AWS profile to collect with |
| `--region REGION` | profile / environment region | AWS region to collect from |
| `--from-json FILE` | | replay a dumped payload; no AWS calls, so `--profile`/`--region` are rejected |
| `--dump-json FILE` | | write the collected payload here for later `--from-json` runs |
| `--as-of TIMESTAMP` | payload `collected_at` under `--from-json`, otherwise now | age the secrets against a fixed instant, e.g. `2026-10-20T12:00:00Z` |
| `--unused-days N` | `90` | `unused-secret` fires on a secret unread for N days |
| `--rotation-grace-days N` | `7` | slack allowed past the rotation interval before `rotation-stale` fires |
| `--require-tags KEYS` | | comma-separated tag keys every secret must carry; turns `untagged` into a real ownership check instead of a "has no tags at all" check |
| `--credential-pattern REGEX` | built-in heuristic | replace the regex deciding which secrets the rotation rules apply to with your own naming convention |
| `--all-secrets` | off | apply the rotation rules to every secret, not only the ones whose name, description or tags read like a credential |
| `--owners FILE` | | YAML mapping of secret-name glob (or exact ARN) to owner; the first matching glob wins |
| `--owner-tag KEY` | `owner` | tag key read when no `--owners` glob matches; exact key first, then any case; `''` turns it off |
| `--schedule` | off | print the rotation schedule instead of findings; always exits `0` |
| `--interval PATTERN=DURATION` | | rotation policy per class of secret, e.g. `db\|password=90d,signing=365d,default=180d`; repeatable |
| `--remind-before DURATION` | `14d` | how far ahead a rotation turns `due-soon`, and the calendar alarm offset |
| `--export-ics FILE` | | write the schedule as an iCalendar file; works with or without `--schedule` |
| `--format text\|json` | `text` | output format |
| `--group-by secret\|owner` | `secret` | group the text report (findings or schedule) by secret or by owner |
| `--severity low\|medium\|high` | `low` | drop findings below this severity; `high` keeps what pages someone |
| `--ignore-rule RULE` | | skip a rule; repeatable, and each value may be a comma-separated list |
| `--ignore-secret NAME` | | skip a secret by name or ARN; a trailing `*` matches a prefix; repeatable |
| `--fail-on RULES` | | comma-separated rules that make the run exit `1` |
| `--version` | | print the version and exit |

See [`examples/`](examples/) for a credential-free dump and its full output.

## Owners

A finding in a channel nobody owns gets read by nobody. Every finding and every schedule
row carries an `owner`, resolved in this order:

1. the first glob in the `--owners` file that matches the secret name (or an entry that is
   the secret's exact ARN);
2. the secret's `owner` tag (`--owner-tag` picks the key; an exact key match wins over a
   different-case one, so `Owner` and `owner` both work).

```yaml
# owners.yaml: first match wins, so specific globs go above broad ones
prod/stripe/*: payments-oncall@example.com
legacy/*: platform
```

The globs are shell-style (`fnmatch`), and `*` also matches `/`. A live secret with neither
gets `unowned-secret` (medium), which is different from `untagged`: `untagged` checks tag
keys, `unowned-secret` checks that there is someone to page. JSON findings carry `"owner"`
(`null` when unowned); text findings show it next to the secret, or group under it:

```console
$ aws-secretsmanager-audit --from-json examples/sample-dump.json \
    --owners examples/owners.yaml --group-by owner --severity high
integrations
  prod/partner/webhook-secret
    high   rotation-disabled         rotation is not enabled; value last changed 2022-09-10 (1501d ago)
    high   wildcard-resource-policy  statement PartnerMigration2022 allows account 999988887777 (outside 111122223333) with no Condition
...
```

## Rotation schedule

The rules tell you what is already late. `--schedule` tells you what comes due next and who
has to do it, so the rotation goes on a calendar before it becomes a `rotation-stale`:

```console
$ aws-secretsmanager-audit --from-json examples/sample-dump.json --schedule \
    --owners examples/owners.yaml --interval 'db|password=90d,ssh|signing=365d'
2021-11-23  1791d late  overdue      platform                     legacy/jenkins-ssh-key
    every 365d (--interval ssh|signing); created, never rotated 2020-11-23
2024-05-30  873d late   overdue      payments-oncall@example.com  prod/stripe/api-key
    every 90d (rotation rules); created, never rotated 2024-03-01
2025-08-17  429d late   overdue      sre                          staging/grafana-admin-password
    every 90d (--interval db|password); created, never rotated 2025-05-19
2026-08-16  65d late    overdue      orders                       prod/orders/db-password
    every 30d (rotation rules); last rotated 2026-07-17
2026-11-03  in 13d      due-soon     billing                      prod/billing/db-password
    every 30d (rotation rules); last rotated 2026-10-04
2027-04-01  in 162d     ok           sre                          prod/metrics/readonly-token
    every 365d (rotation rules); last rotated 2026-04-01
-                       unscheduled  integrations                 prod/partner/webhook-secret
    no interval: rotation is off and no --interval matches; created, never rotated 2022-09-10

7 secret(s) on the schedule as of 2026-10-20, reminding 14d ahead — overdue=4 due-soon=1 ok=1 unscheduled=1
```

Per secret:

- **interval.** The configured `AutomaticallyAfterDays` or `rate()`, unless an `--interval`
  pattern gives a shorter one: a database password configured for 365 days under a 90 day
  policy is due by the policy. A longer policy never relaxes the configuration. PATTERN is
  a case-insensitive regex over name, description and tags; the first match wins, and
  `default=N` covers everything no pattern matched. Commas separate items, so a pattern
  cannot contain one.
- **counted from.** `LastRotatedDate`, or `CreatedDate` for a secret that never rotated.
  `LastChangedDate` is not used, because Secrets Manager moves it on any modification,
  including a tag or description edit.
- **status.** `due-soon` within `--remind-before` of the due date, `due` past it but inside
  `--rotation-grace-days`, `overdue` past the grace (the same line `rotation-stale` uses),
  `unscheduled` when there is no interval (rotation off or a cron schedule, and no
  `--interval` match).

The schedule covers the same secrets the rotation rules do: live, credential-shaped (or all
with `--all-secrets`), minus `--ignore-secret`. `--format json` gives one object per row
with `due`, `days_left`, `status`, `owner` and where the interval came from.

`--export-ics rotation.ics` writes one all-day event per due date with a display alarm
`--remind-before` ahead. An owner that is an email address is added as the attendee. The
UID is derived from the ARN and DTSTAMP from the as-of instant, so replaying a dump gives
the same file, and a calendar subscribed to it moves a secret's event after a rotation
instead of adding a second one.

## How it works

Collection and judgement are separate on purpose. `collect.py` is the only module that
imports boto3, and it imports it inside the function; it paginates `list_secrets`
(including planned deletions), adds `describe_secret` and `get_resource_policy` per secret,
and round-trips the whole thing through `json` so every `datetime` becomes a string exactly
once. The rule engine takes that plain dict and nothing else. `schedule.py` reads the same
dict to work out due dates, and `owners.py` resolves the owner both of them attach.

That split is what makes the suite real: every test is a JSON fixture under
`tests/fixtures/`, CI runs with no AWS account and no credentials, and `--from-json` is not
a debug mode but the same code path a live run takes after collection.

A dump also carries `collected_at`, and `--from-json` ages secrets against that instant
rather than the wall clock. Replaying yesterday's dump tomorrow gives byte-for-byte the same
report instead of silently adding a day to every age.

## One note on the heuristic

`rotation-disabled` deliberately does not fire on every secret. Plenty of things in Secrets
Manager are not credentials — feature-flag blobs, kubeconfigs, a JSON document someone
parked there — and telling you to rotate a feature flag teaches you to ignore the tool. So a
secret qualifies when its name, description or tags match a credential pattern, or when
somebody already configured rotation on it, which is its own admission of what it holds.

That is a heuristic and it will miss things, which is why `--all-secrets` exists and why the
pattern is replaceable. Tune it once for your naming convention and keep it in the CI
invocation.

## License

MIT
