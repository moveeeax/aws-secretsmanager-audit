# aws-secretsmanager-audit

[![ci](https://github.com/moveeeax/aws-secretsmanager-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-secretsmanager-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Secrets Manager is where a credential goes to be forgotten. You create the secret during a
migration, wire it into one task definition, enable rotation "later", and three years on
nobody can tell you whether that database password has ever changed, who can read it, or
whether the rotation Lambda has been failing since its runtime was deprecated.

The console shows a list of names and a green checkmark per secret, which tells you none of
that. This tool answers it: one pass over the account, nine rules, a text table or JSON, and
an exit code you can gate a pipeline on.

## What it checks

| rule | severity | fires when |
| --- | --- | --- |
| `rotation-disabled` | high | `RotationEnabled` is false on a credential-shaped secret |
| `never-rotated` | high | rotation is enabled and `LastRotatedDate` is absent — configured, never ran |
| `rotation-stale` | high | `LastRotatedDate` is older than the rotation interval plus the grace window |
| `wildcard-resource-policy` | high | an `Allow` statement with `Principal: "*"` or an outside account and no `Condition` |
| `unused-secret` | medium | `LastAccessedDate` older than `--unused-days`, or no recorded access at all |
| `pending-deletion` | medium | `DeletedDate` is set; reports the days left in the recovery window |
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

prod/orders/db-password
  high   rotation-stale            rotates every 30d but last rotated 2026-07-17 (95d ago, 58d past the 7d grace)

prod/partner/webhook-secret
  high   rotation-disabled         rotation is not enabled; value last changed 2022-09-10 (1501d ago)
  high   wildcard-resource-policy  statement PartnerMigration2022 allows account 999988887777 (outside 111122223333) with no Condition

prod/stripe/api-key
  high   never-rotated             rotation is enabled but has never run; rotation lambda rotate-stripe-key

staging/grafana-admin-password
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
wrong (unknown rule name, unreadable payload, unparseable `--as-of`).

Useful flags:

- `--require-tags Owner,Env` — turn `untagged` into a real ownership check instead of a
  "has no tags at all" check.
- `--all-secrets` — apply the rotation rules to every secret, not only the ones whose name,
  description or tags read like a credential.
- `--credential-pattern REGEX` — replace that heuristic with your own naming convention.
- `--severity high` — drop the hygiene noise and keep what pages someone.
- `--as-of 2026-10-20T12:00:00Z` — age the secrets against a fixed instant.

See [`examples/`](examples/) for a credential-free dump and its full output.

## How it works

Collection and judgement are separate on purpose. `collect.py` is the only module that
imports boto3, and it imports it inside the function; it paginates `list_secrets`
(including planned deletions), adds `describe_secret` and `get_resource_policy` per secret,
and round-trips the whole thing through `json` so every `datetime` becomes a string exactly
once. The rule engine takes that plain dict and nothing else.

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
