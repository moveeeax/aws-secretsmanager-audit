# examples

`sample-dump.json` is a nine-secret account in the shape `--dump-json` writes. It needs no
credentials, so it is the fastest way to see what the tool says before you point it at prod.

```console
$ aws-secretsmanager-audit --from-json examples/sample-dump.json
legacy/jenkins-ssh-key
  high   rotation-disabled         rotation is not enabled; value last changed 2020-11-23 (2156d ago)
  medium unowned-secret            no owner to route findings to: no 'owner' tag
  medium unused-secret             last read 2025-02-11 (616d ago, threshold 90d)
  low    default-kms-key           no KmsKeyId set, so it uses the aws/secretsmanager managed key and grants cannot be audited per team
  low    no-description            no description, so its purpose is guesswork
  low    untagged                  no tags at all, so ownership is unknowable

ops/decommissioned-vpn-psk  (owner: network)
  medium pending-deletion          scheduled for deletion on 2026-11-12 (23d of recovery window left)

prod/orders/db-password  (owner: orders)
  high   rotation-stale            rotates every 30d but last rotated 2026-07-17 (95d ago, 58d past the 7d grace)

prod/partner/webhook-secret  (owner: integrations)
  high   rotation-disabled         rotation is not enabled; value last changed 2022-09-10 (1501d ago)
  high   wildcard-resource-policy  statement PartnerMigration2022 allows account 999988887777 (outside 111122223333) with no Condition
  low    default-kms-key           no KmsKeyId set, so it uses the aws/secretsmanager managed key and grants cannot be audited per team

prod/stripe/api-key  (owner: payments)
  high   never-rotated             rotation is enabled but has never run; rotation lambda rotate-stripe-key

staging/grafana-admin-password  (owner: sre)
  high   rotation-disabled         rotation is not enabled; value last changed 2025-05-19 (519d ago)
  low    default-kms-key           no KmsKeyId set, so it uses the aws/secretsmanager managed key and grants cannot be audited per team

14 finding(s) across 6 of 9 secret(s) — high=6 medium=3 low=5
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

`owners.yaml` is a two-line ownership file for the same dump. With it, `legacy/jenkins-ssh-key`
stops being `unowned-secret`, and the Stripe key goes to an on-call address instead of its
`payments` tag. The rotation schedule for the dump, with a calendar file:

```console
$ aws-secretsmanager-audit --from-json examples/sample-dump.json --schedule \
    --owners examples/owners.yaml --interval 'db|password=90d,ssh|signing=365d' \
    --export-ics /tmp/rotation.ics
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
