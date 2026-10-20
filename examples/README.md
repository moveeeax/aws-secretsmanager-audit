# examples

`sample-dump.json` is a nine-secret account in the shape `--dump-json` writes. It needs no
credentials, so it is the fastest way to see what the tool says before you point it at prod.

```console
$ aws-secretsmanager-audit --from-json examples/sample-dump.json
legacy/jenkins-ssh-key
  high   rotation-disabled         rotation is not enabled; value last changed 2020-11-23 (2156d ago)
  medium unused-secret             last read 2025-02-11 (616d ago, threshold 90d)
  low    default-kms-key           no KmsKeyId set, so it uses the aws/secretsmanager managed key and grants cannot be audited per team
  low    no-description            no description, so its purpose is guesswork
  low    untagged                  no tags at all, so ownership is unknowable

ops/decommissioned-vpn-psk
  medium pending-deletion          scheduled for deletion on 2026-11-12 (23d of recovery window left)

prod/orders/db-password
  high   rotation-stale            rotates every 30d but last rotated 2026-07-17 (95d ago, 58d past the 7d grace)

prod/partner/webhook-secret
  high   rotation-disabled         rotation is not enabled; value last changed 2022-09-10 (1501d ago)
  high   wildcard-resource-policy  statement PartnerMigration2022 allows account 999988887777 (outside 111122223333) with no Condition
  low    default-kms-key           no KmsKeyId set, so it uses the aws/secretsmanager managed key and grants cannot be audited per team

prod/stripe/api-key
  high   never-rotated             rotation is enabled but has never run; rotation lambda rotate-stripe-key

staging/grafana-admin-password
  high   rotation-disabled         rotation is not enabled; value last changed 2025-05-19 (519d ago)
  low    default-kms-key           no KmsKeyId set, so it uses the aws/secretsmanager managed key and grants cannot be audited per team

13 finding(s) across 6 of 9 secret(s) — high=6 medium=2 low=5
```

Three secrets in the dump are deliberately clean and worth reading as the negative cases:

- `prod/billing/db-password` rotates every 30 days and did so 16 days ago.
- `prod/metrics/readonly-token` is 202 days into a 365 day cycle, which is not late.
- `prod/internal/shared-config` has a `Principal: "*"` resource policy narrowed by
  `aws:PrincipalOrgID`, so it is not a wildcard finding.

Gate a pipeline on the two that actually page someone:

```console
$ aws-secretsmanager-audit --from-json examples/sample-dump.json \
    --fail-on rotation-stale,wildcard-resource-policy --severity high >/dev/null
$ echo $?
1
```
