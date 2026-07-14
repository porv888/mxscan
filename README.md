# MXScan

Email security and deliverability monitoring platform built on Laravel.

## What it does

- DNS security scans (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI)
- Blacklist monitoring across RBL providers
- SPF analysis with lookup counting
- Delivery monitoring via `monitor+TOKEN@mxscan.me`
- DMARC aggregate report ingestion and visibility
- Domain and SSL expiry detection
- Plan-based access: Freemium, Premium, Ultra

## Documentation

All project documentation lives in [`docs/README.md`](docs/README.md):

- [Environments & databases](docs/README.md#environments)
- [Deployment](docs/README.md#deployment)
- [Scheduler & cron](docs/README.md#scheduler)
- [Plans & entitlements](docs/README.md#plans-and-entitlements)
- [Operations & troubleshooting](docs/README.md#operations)

## Quick start (local / dev)

```bash
cp .env.example .env
# Configure DB, mail, Stripe, IMAP keys in .env
composer install
php artisan key:generate
php artisan migrate
php artisan db:seed --class=PlanSeeder
php artisan serve
```

## Environments

| Environment | URL | Path | Database |
|-------------|-----|------|----------|
| Production | https://app.mxscan.me | `/home/mxscan/public_html/app.mxscan.me` | `zed2_email` (no prefix) |
| Development | https://dev.mxscan.me | `/home/mxscan/public_html/dev.mxscan.me` | `zed2_devmx` (`dev_` prefix) |

**Never run `migrate:fresh` or `db:wipe` against a shared or production database.**

## License

Proprietary. All rights reserved.
