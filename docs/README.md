# MXScan Documentation

Last updated: July 2026

## Table of contents

1. [Environments](#environments)
2. [Database setup](#database-setup)
3. [Deployment](#deployment)
4. [Scheduler](#scheduler)
5. [Plans and entitlements](#plans-and-entitlements)
6. [Core features](#core-features)
7. [Operations](#operations)

---

## Environments

MXScan runs as two separate Laravel apps on the same server.

| | Production | Development |
|---|---|---|
| **URL** | https://app.mxscan.me | https://dev.mxscan.me |
| **Path** | `/home/mxscan/public_html/app.mxscan.me` | `/home/mxscan/public_html/dev.mxscan.me` |
| **Database** | `zed2_email` | `zed2_devmx` |
| **Table prefix** | _(none)_ | `dev_` |
| **Session cookie** | `mxscan_session` | `mxscan_dev_session` |
| **Session domain** | `.mxscan.me` | `dev.mxscan.me` |
| **Git remote** | `origin/master` (pull deploy) | Same repo, local branch work |

Dev and production use **separate databases**. They must never share one database or table prefix.

### Environment files

Copy `.env.example` and configure:

- `APP_URL`, `APP_KEY`, `APP_DEBUG`
- `DB_*` — database name, credentials, and `DB_PREFIX` (dev only)
- `SESSION_*` — driver, cookie name, domain
- `STRIPE_*` — billing
- `SENDGRID_API_KEY` — transactional email
- `DMARC_IMAP_*` — DMARC report ingestion mailbox
- `PLAN_LIMIT_*` — plan domain caps (see [Plans](#plans-and-entitlements))

---

## Database setup

### Fresh dev database

```bash
cd /home/mxscan/public_html/dev.mxscan.me
php artisan config:clear
php artisan migrate
php artisan db:seed --class=PlanSeeder
php artisan db:seed --class=SettingsSeeder   # optional
```

With `DB_PREFIX=dev_`, Laravel creates tables like `dev_users`, `dev_domains`, etc.

### Fresh production database

Only when intentionally rebuilding production (destroys all data):

```bash
cd /home/mxscan/public_html/app.mxscan.me
php artisan migrate --force
php artisan db:seed --class=PlanSeeder --force
php artisan db:seed --class=SettingsSeeder --force
php artisan optimize:clear
```

Production uses **no** `DB_PREFIX`. Tables are `users`, `domains`, `sessions`, etc.

### Critical safety rules

| Command | Safe on dev (`zed2_devmx`) | Safe on production (`zed2_email`) |
|---------|---------------------------|-----------------------------------|
| `php artisan migrate` | Yes | Yes (applies pending migrations) |
| `php artisan migrate:fresh` | Only if you accept wiping dev data | **Never** |
| `php artisan db:wipe` | Only if you accept wiping dev data | **Never** |

`migrate:fresh` drops **all tables in the database**, not just prefixed ones. Running it against a shared database previously caused a production outage.

### Migrations with table prefixes

Migrations must use `Schema::` helpers (not hardcoded table names in raw SQL) so `DB_PREFIX` works. If a migration uses `DB::statement('ALTER TABLE users ...')`, wrap the table name:

```php
$table = Schema::getConnection()->getTablePrefix() . 'users';
DB::statement("ALTER TABLE `{$table}` ...");
```

---

## Deployment

### Dev → production workflow

```bash
# 1. Commit and push from dev
cd /home/mxscan/public_html/dev.mxscan.me
git add -A
git commit -m "Your change description"
git push origin master

# 2. Pull on production
cd /home/mxscan/public_html/app.mxscan.me
git pull origin master

# 2b. Preflight (fails if legacy SPF fallback is still present)
php artisan deploy:preflight

# 3. Run migrations if schema changed
php artisan migrate --force

# 4. Rebuild caches
php artisan optimize:clear
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

### Post-deploy checks

```bash
# Verify native SPF pipeline is mandatory (no legacy fallback)
php artisan deploy:preflight

# Verify site responds
curl -sI https://app.mxscan.me/

# Check migration status
php artisan migrate:status

# Sync Freemium plan limit after entitlement deploy
php artisan plans:sync-limits
```

### What not to deploy via git

- `.env` (environment-specific secrets)
- `vendor/` (run `composer install` on server if needed)
- User uploads / `storage/` runtime files

---

## Scheduler

Laravel scheduler must run every minute via cron:

```cron
* * * * * cd /home/mxscan/public_html/app.mxscan.me && php artisan schedule:run >> /dev/null 2>&1
```

For dev (if scheduler testing needed):

```cron
* * * * * cd /home/mxscan/public_html/dev.mxscan.me && php artisan schedule:run >> /dev/null 2>&1
```

### Scheduled tasks

| Task | Frequency | Command / job |
|------|-----------|---------------|
| SPF daily check | Daily | `SpfCheckJob` for active domains |
| DMARC poller | Every 5 min | `mail:fetch-dmarc` (when `MAIL_POLL_ENABLED=true`) |
| SSL expiry detection | Daily 03:00 | `DetectSslExpiry` job |
| Domain expiry detection | Daily 03:15 | `DetectDomainExpiry` job |
| Expiry reminders | Daily 08:00 | Email at 30/7/1 days before expiry |
| Weekly reports | Monday 07:00 | `SendWeeklyReport` job |
| Delivery monitoring | Every 5 min | `monitoring:collect` |
| User scheduled scans | Every minute | `scans:scheduled` |

### Manual commands

```bash
php artisan monitoring:collect -v      # Delivery inbox collection
php artisan mail:fetch-dmarc -v        # DMARC IMAP fetch
php artisan scans:scheduled --dry-run  # Preview due scheduled scans
php artisan plans:sync-limits          # Update Freemium domain_limit in DB
```

---

## Plans and entitlements

Plan limits are defined in `config/plans.php` and seeded via `PlanSeeder`.

| Plan | Domains | Key features |
|------|---------|--------------|
| **Freemium** | 1 | Manual full scans on one active domain |
| **Premium** | 10 | Automations, monitoring, DMARC Activity, tools, partial scans |
| **Ultra** | 50 | Premium features + API access |

### Entitlement service (dev branch)

`App\Services\Entitlement\EntitlementService` is the single source of truth for plan gating.

- Feature constants: `App\Services\Entitlement\EntitlementFeature`
- Middleware: `entitlement:{feature}` (registered in `bootstrap/app.php`)
- Free users with multiple domains: oldest `created_at` domain stays active; others are plan-locked (view-only)

Free plan active domain rule (no migration required):

1. Oldest `domains.created_at` ASC, tie-breaker lowest `domains.id`
2. Future: optional `users.free_active_domain_id` if user-selectable active domain is added

### Sync plan limits to database

After changing Freemium limit in config/seeder:

```bash
php artisan plans:sync-limits
```

---

## Core features

### DNS security scan

Full scan checks MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, and blacklist status. Triggered manually or via automations (paid).

DMARC policy analysis runs through the native `DmarcCheck` pipeline (`EmailSecurityScanService`); enforcement is scored by `DmarcScoreRule` (30-point tier). Reporting gaps are recommendations only (Option A).

Key code: `App\Services\EmailSecurityScanService`, `App\Domain\EmailSecurity\Checks\DMARC\DmarcCheck`, `App\Http\Controllers\ScanController`

### Blacklist monitoring

Checks domain IPs against configured RBL providers in `config/rbl.php`.

Key code: `App\Services\BlacklistChecker`

### SPF analysis

Recursive SPF resolution with lookup counting. Daily scheduled checks plus on-demand analysis (paid).

Key code: `App\Services\Spf\SpfResolver`, `App\Jobs\SpfCheckJob`

### Delivery monitoring

Test emails sent to `monitor+TOKEN@mxscan.me` are collected from Dovecot/Exim subfolders (`INBOX.*`) and analyzed for SPF/DKIM/DMARC pass/fail and time-to-inbox.

Key code: `App\Console\Commands\CollectDeliveryMonitoring`, delivery check models

### DMARC Activity

DMARC aggregate reports are fetched from IMAP, parsed, and stored for per-domain visibility (paid).

Key code: `App\Services\Dmarc\*`, `php artisan mail:fetch-dmarc`

Poller config: `DMARC_IMAP_*` and `MAIL_POLL_ENABLED` in `.env`

### Expiry detection

Domain expiry via RDAP/WHOIS; SSL expiry via live TLS handshake. Alerts at configured thresholds.

Key code: `App\Jobs\DetectDomainExpiry`, `App\Jobs\DetectSslExpiry`, `config/expiry.php`

### Billing

Stripe via Laravel Cashier. Webhook at `/api/stripe/webhook`.

Key code: `App\Http\Controllers\BillingController`, `Billing\PlanController`

---

## Operations

### Common issues

**500 error: `Table '...sessions' doesn't exist`**

- Session driver is `database` but `sessions` table is missing.
- Fix: run `php artisan migrate` or switch `SESSION_DRIVER=file` temporarily.

**500 after database incident**

- Verify production tables exist: `users`, `sessions`, `domains`, `migrations` (no `dev_` prefix).
- Check `storage/logs/laravel-*.log` for the exact missing table.

**Dev migrations fail with prefix**

- Ensure raw SQL migrations use prefixed table names (see [Database setup](#database-setup)).

**Scheduled scans not running**

- Confirm cron is calling `schedule:run` every minute.
- Check `cache` driver — scheduler mutex needs writable cache (file or database table).

### Logs

```bash
tail -f storage/logs/laravel-$(date +%Y-%m-%d).log
```

### Running tests (dev)

```bash
php artisan test --filter=Entitlement
php artisan test --filter=FreePlan
php artisan test --filter=Dmarc
```

Tests that use `RefreshDatabase` against MySQL may fail if migrations are incomplete; prefer the SQLite test traits in `tests/Concerns/`.

### Admin access

After a database rebuild, create users via registration or tinker:

```bash
php artisan tinker
# User::create([...]) with hashed password and role admin if needed
```

---

## Repository layout

```
app/
  Http/Controllers/     # Web and API controllers
  Services/               # Business logic (Scanner, DMARC, Entitlement, etc.)
  Jobs/                   # Queued work
  Models/                 # Eloquent models
config/                   # App, plans, rbl, expiry config
database/migrations/      # Schema migrations
resources/views/          # Blade templates
routes/web.php            # Authenticated app routes
routes/api.php            # API + Stripe webhook
docs/README.md            # This file
```
