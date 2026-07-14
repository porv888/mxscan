# Native SPF Engine — Release `spf-native-v1.0.0-rc1`

## Release record

| Field | Value |
|-------|-------|
| **Release identifier** | `spf-native-v1.0.0-rc1` |
| **RC commit hash** | `1209851f37aeaeed56395d0ca0108950520a083a` |
| **Pre-native production release** | `53feca8923fec5abe1f15c8ce39bcb979424d7e6` |
| **Rollback release** | `53feca8923fec5abe1f15c8ce39bcb979424d7e6` |
| **Migrations required** | None |
| **Schema changes** | None |
| **Configuration change (production activation)** | `EMAIL_SECURITY_SPF_ENGINE=native` in production `.env` only |

## Verification at release cut

| Suite | Result |
|-------|--------|
| Native rollout bundle (28 tests) | 28 passed, 196 assertions |
| `--filter=EmailSecurity` | 121 passed, 429 assertions |

## Deployment procedure

### Phase A — Code deploy (engine stays legacy)

```bash
cd /home/mxscan/public_html/app.mxscan.me
git pull origin master
php artisan migrate --force
php artisan optimize:clear
php artisan config:cache
php artisan route:cache
php artisan view:cache
php artisan config:show email-security   # expect: spf_engine = legacy
```

### Phase B — Production activation (after dev soak gate)

```bash
# Edit production .env:
EMAIL_SECURITY_SPF_ENGINE=native

php artisan optimize:clear
php artisan config:cache
php artisan queue:restart
php artisan config:show email-security   # expect: spf_engine = native
```

### Rollback

```bash
EMAIL_SECURITY_SPF_ENGINE=legacy
php artisan optimize:clear
php artisan config:cache
php artisan queue:restart
```

Code rollback (if required): `git checkout 53feca8923fec5abe1f15c8ce39bcb979424d7e6`

## Out of scope

- UI changes
- DMARC changes
- Billing changes
- Infrastructure changes
- Legacy runtime removal (`SpfCheckJob` still uses `SpfResolver`)

## Development soak gate (required before Phase B)

Minimum: 7 calendar days, ≥50 completed scans, no score invariant failures.

See rollout plan Section 2 in agent transcript for SQL/log queries.

## Smoke scenarios (production, post-activation)

Operator-owned test domains only. Nine scenarios: missing SPF, valid `-all`, M365 include, Google include, multiple records, 10 lookups, 11 lookups, redirect, unsupported macro.
