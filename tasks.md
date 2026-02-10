# MXScan — Improvement Tasks

> Generated: Feb 10, 2026
> Priority: P0 = critical, P1 = high, P2 = medium, P3 = low

---

## Task 1 — Implement or Hide Stub Tools
**Priority:** P0
**Effort:** 2–4 days per tool (implement) / 1 hour (hide)
**Files:**
- `app/Http/Controllers/ToolsController.php`
- `resources/views/domains/hub/tools.blade.php`
- `routes/web.php` (lines 147–149)

### Problem
Three tools are advertised in the UI but contain zero logic — they just flash "completed" and redirect. Customers clicking them get nothing. This damages credibility and trust.

### Option A — Implement (Recommended)

#### A1. SMTP Test Tool
Test outbound SMTP connectivity from a user's domain. Show whether their MX hosts accept connections, support STARTTLS, and respond correctly.

**Implementation steps:**
1. Add a form in the tools view: input = domain (pre-filled), optional = port (25/465/587)
2. In `ToolsController::smtpTest()`:
   - Resolve MX records for the domain via `DnsClient::getMx()`
   - For each MX host, open a socket connection (`fsockopen` or `stream_socket_client`) on port 25 with a 5-second timeout
   - Send `EHLO mxscan.me`, capture the banner and capabilities
   - Check for STARTTLS support in the EHLO response
   - If STARTTLS is advertised, attempt `STARTTLS` upgrade and verify TLS version/cipher
   - Close the connection gracefully with `QUIT`
3. Return results: MX host, banner, STARTTLS support (yes/no), TLS version, response time
4. Store results in session flash for display, or return JSON for AJAX

**Key classes to use/create:**
- `App\Services\SmtpTester` — new service class
- Reuse `App\Services\Dns\DnsClient` for MX resolution

#### A2. BIMI Check Tool
Validate BIMI (Brand Indicators for Message Identification) DNS record and SVG logo.

**Implementation steps:**
1. Add a form: input = domain
2. In `ToolsController::bimiCheck()`:
   - Query TXT record at `default._bimi.{domain}` via `DnsClient::getTxt()`
   - Parse the BIMI record: extract `v=`, `l=` (logo URL), `a=` (authority URL)
   - Validate the `l=` URL: must be HTTPS, must point to an SVG Tiny PS file
   - Fetch the SVG via `Http::get()`, verify Content-Type is `image/svg+xml`
   - Validate SVG is Tiny PS compliant (basic: check for `<svg` root, `baseProfile="tiny-ps"`)
   - If `a=` is present, note VMC certificate info
3. Return: record found/missing, logo URL, logo preview, validation status

**Key classes to create:**
- `App\Services\BimiChecker` — new service class

#### A3. SPF Wizard Tool
Interactive wizard that helps users build an SPF record from scratch.

**Implementation steps:**
1. Create a multi-step form view (or single-page with JS sections):
   - Step 1: Enter domain → auto-detect current MX records
   - Step 2: Select email providers from a checklist (Google Workspace, Microsoft 365, Mailgun, SendGrid, Amazon SES, Postmark, etc.) — pre-check any detected from MX
   - Step 3: Add custom IP addresses or includes
   - Step 4: Choose qualifier (`-all`, `~all`, `?all`)
   - Step 5: Preview generated SPF record with copy button + lookup count estimate
2. In `ToolsController::spfWizard()`:
   - Accept form data, validate
   - Use `SpfResolver` to count lookups for the generated record
   - Return the generated record with lookup count and warnings
3. Reuse existing `ScannerService::generateSpfRecord()` logic as a starting point

**Key classes to extend:**
- `App\Services\Spf\SpfResolver` — reuse `resolve()` to validate generated records

### Option B — Hide (Quick Fix)
If implementation is deferred, remove the tools from the UI immediately:
1. Remove or comment out the three routes in `routes/web.php` (lines 147–149)
2. Hide the tools section in `resources/views/domains/hub/tools.blade.php`
3. Remove any nav links pointing to these tools

---

## Task 2 — Add DKIM Check to Main DNS Scan
**Priority:** P0
**Effort:** 2–3 days
**Files:**
- `app/Services/ScannerService.php`
- `app/Services/Dns/DnsClient.php`
- `resources/views/scans/show.blade.php` (and related scan result views)
- `app/Services/MonitoringService.php` (add `dkim_ok` to snapshots)

### Problem
The main DNS scan checks MX, SPF, DMARC, TLS-RPT, MTA-STS but completely ignores DKIM. DKIM is a core email authentication pillar. The security score (max 100) allocates 0 points to DKIM.

### Implementation Steps

1. **Define common DKIM selectors to probe** — Create a config array:
   ```php
   // config/dkim.php
   return [
       'selectors' => [
           'google', 'selector1', 'selector2',    // Google / Microsoft 365
           'k1', 'k2', 'k3',                      // Mailchimp / Mandrill
           'default', 'mail', 'dkim',              // Generic
           's1', 's2',                             // Generic
           'smtp', 'email',                        // Generic
           'protonmail', 'protonmail2', 'protonmail3', // Protonmail
           'sendgrid', 'smtpapi',                  // SendGrid
           'mailgun',                              // Mailgun
           'amazonses',                            // AWS SES (often "xxxxxxxxxx._domainkey")
           'postmark',                             // Postmark
           'cm',                                   // Campaign Monitor
           'turbo-smtp',                           // TurboSMTP
       ],
   ];
   ```

2. **Add DKIM check to `ScannerService::scanDomain()`** — After the SPF check block:
   ```php
   // Check DKIM selectors
   $dkimSelectors = config('dkim.selectors', []);
   $dkimFound = [];
   foreach ($dkimSelectors as $selector) {
       $dkimDomain = "{$selector}._domainkey.{$domain}";
       $dkimRecords = dns_get_record($dkimDomain, DNS_TXT);
       if (!empty($dkimRecords)) {
           foreach ($dkimRecords as $rec) {
               if (isset($rec['txt']) && str_contains($rec['txt'], 'p=')) {
                   $dkimFound[] = [
                       'selector' => $selector,
                       'record' => $rec['txt'],
                   ];
                   break;
               }
           }
       }
   }
   
   $records['DKIM'] = !empty($dkimFound)
       ? ['status' => 'found', 'data' => $dkimFound]
       : ['status' => 'missing'];
   
   if (!empty($dkimFound)) {
       $score += 15; // Award points for DKIM
   }
   ```

3. **Adjust score weights** — Current max is 105 before capping. With DKIM added (15 pts), rebalance:
   - MX: 15 (was 20)
   - SPF: 20 (keep)
   - DKIM: 15 (new)
   - DMARC: 20 (keep)
   - TLS-RPT: 10 (was 15)
   - MTA-STS: 20 (keep)
   - Qualifier bonuses: keep as-is

4. **Add DKIM to recommendations** in `generateRecommendations()`:
   ```php
   if ($records['DKIM']['status'] === 'missing') {
       $recommendations[] = [
           'type' => 'DKIM',
           'title' => 'Configure DKIM signing',
           'value' => 'Enable DKIM in your mail server or email provider settings',
           'description' => 'DKIM adds a digital signature to outgoing emails, proving they haven\'t been tampered with in transit.',
       ];
   }
   ```

5. **Update scan result views** to display DKIM results alongside SPF/DMARC.

6. **Update `MonitoringService`** — Add `dkim_ok` boolean to `ScanSnapshot` and the normalization logic so incidents can be raised when DKIM disappears.

7. **Migration** — Add `dkim_ok` column to `scan_snapshots` table.

---

## Task 3 — Build a Public Scan Page
**Priority:** P1
**Effort:** 3–5 days
**Files:**
- New: `app/Http/Controllers/PublicScanController.php`
- New: `resources/views/public/scan.blade.php`
- `routes/web.php`

### Problem
The root URL (`/`) redirects to login. There's no public-facing tool for lead generation or SEO. Competitors like MXToolbox thrive on free public lookups.

### Implementation Steps

1. **Create route** (outside auth middleware):
   ```php
   Route::get('/', [PublicScanController::class, 'index'])->name('public.scan');
   Route::post('/scan', [PublicScanController::class, 'scan'])->name('public.scan.run');
   Route::get('/scan/{domain}', [PublicScanController::class, 'result'])->name('public.scan.result');
   ```

2. **Create `PublicScanController`**:
   - `index()` — Render the landing page with a domain input field and CTA
   - `scan()` — Validate domain, run a lightweight DNS scan (MX, SPF, DKIM, DMARC only — skip blacklist), return results
   - `result()` — Show results page with score, found/missing records, and recommendations
   - Rate-limit: 5 scans/minute per IP (use Laravel's `throttle` middleware)
   - Limit displayed detail: show status (found/missing) and score, but blur or gate detailed records and recommendations behind signup

3. **Landing page design** (`resources/views/public/scan.blade.php`):
   - Hero section: "Check your domain's email security in seconds"
   - Single input field + "Scan" button
   - Below: brief feature highlights (SPF, DKIM, DMARC, Blacklist, Delivery Monitoring)
   - Social proof section (if available)
   - Pricing CTA

4. **Results page**:
   - Score gauge (0–100)
   - Record status badges (MX ✓, SPF ✓, DKIM ✗, DMARC ✗, etc.)
   - Blurred recommendations section with "Sign up to see full details" CTA
   - "Monitor this domain" CTA → leads to registration

5. **SEO considerations**:
   - Add meta tags, Open Graph tags
   - Make result pages indexable: `/scan/example.com` as shareable URLs
   - Add structured data (FAQ schema about email security)

6. **Update root route**: Change `/` from login redirect to the public scan page. Authenticated users can still be redirected to dashboard via middleware check.

---

## Task 4 — Fix DnsClient to Surface Failures
**Priority:** P1
**Effort:** 1–2 days
**Files:**
- `app/Services/Dns/DnsClient.php`
- `app/Services/Spf/SpfResolver.php`
- `app/Services/ScannerService.php`
- `app/Jobs/SpfCheckJob.php`

### Problem
When `dns_get_record()` returns `false` (network failure, timeout), `DnsClient` returns an empty array silently. Callers can't distinguish "domain has no records" from "DNS lookup failed". This causes false-positive alerts (e.g., the austwick.uk SPF issue).

### Implementation Steps

1. **Create a DNS result DTO**:
   ```php
   // app/Services/Dns/DnsResult.php
   class DnsResult {
       public function __construct(
           public readonly array $records,
           public readonly bool $success,
           public readonly ?string $error = null,
       ) {}
       
       public function failed(): bool { return !$this->success; }
       public function isEmpty(): bool { return empty($this->records); }
   }
   ```

2. **Update `DnsClient` methods** to return `DnsResult` instead of raw arrays:
   - When `dns_get_record()` returns records → `new DnsResult($records, true)`
   - When `dns_get_record()` returns `false` after all retries → `new DnsResult([], false, 'DNS lookup failed after retries')`
   - When exception is thrown → `new DnsResult([], false, $e->getMessage())`
   - When lookup succeeds but returns empty → `new DnsResult([], true)` (genuinely no records)

3. **Update callers**:
   - `SpfResolver::getSpfRecord()` — Check `$result->failed()` and add `TIMEOUT` warning
   - `SpfResolver::resolveCurrent()` — Propagate failure info
   - `SpfCheckJob` — Use failure info to skip change detection on DNS failures
   - `ScannerService` — Log DNS failures in scan results

4. **Backward compatibility**: If changing return types is too disruptive, alternatively add a `getLastError(): ?string` method to `DnsClient` that callers can check after a lookup.

---

## Task 5 — Consolidate Duplicate Routes
**Priority:** P2
**Effort:** 1–2 days
**Files:**
- `routes/web.php`
- `app/Http/Controllers/ScheduleController.php`
- `app/Http/Controllers/ScanController.php`
- Navigation views (sidebar/header)

### Problem
Three overlapping systems exist for schedules and scans, creating maintenance burden and confusion:
- `ScheduleController` at `/dashboard/schedules` (legacy)
- `AutomationController` at `/automations` (new)
- `ScanController` with multiple overlapping entry points

### Implementation Steps

1. **Audit usage** — Check if any views, JS, or external links reference the legacy routes:
   ```bash
   grep -r "schedules\." resources/views/
   grep -r "dashboard.scans" resources/views/
   grep -r "/dashboard/scans" resources/views/
   grep -r "/dashboard/schedules" resources/views/
   ```

2. **Add redirect stubs** for legacy routes (don't break bookmarks):
   ```php
   // Legacy redirects
   Route::get('/dashboard/schedules', fn() => redirect()->route('automations.index'))->name('schedules.index');
   Route::get('/dashboard/scans', fn() => redirect()->route('reports.index'))->name('dashboard.scans');
   Route::get('/dashboard/scans/{scan}', fn($scan) => redirect()->route('reports.show', $scan))->name('scans.show');
   ```

3. **Remove legacy controller code** after 30-day redirect period:
   - Delete `ScheduleController.php` (if `AutomationController` covers all functionality)
   - Consolidate `ScanController` entry points

4. **Remove admin "coming soon" placeholders** — Either implement them or remove the routes and nav links:
   ```php
   // routes/web.php lines 289-294 — Remove these:
   Route::get('/admin/scans', ...);
   Route::get('/admin/plans', ...);
   Route::get('/admin/invoices', ...);
   Route::get('/admin/audit', ...);
   Route::get('/admin/settings', ...);
   ```

5. **Update all navigation views** to point to the canonical route names only.

---

## Task 6 — Add Slack/Webhook Notifications
**Priority:** P2
**Effort:** 3–5 days
**Files:**
- `app/Models/User.php` (stub already exists: `canUseSlackNotifications()`)
- `app/Models/NotificationPref.php`
- New: `app/Services/WebhookNotifier.php`
- `app/Notifications/*.php` (all 7 notification classes)
- `resources/views/settings/notifications.blade.php`
- Migration for webhook URL fields

### Implementation Steps

1. **Migration** — Add columns to `notification_prefs` table:
   ```php
   $table->string('slack_webhook_url')->nullable();
   $table->string('custom_webhook_url')->nullable();
   $table->string('webhook_secret')->nullable(); // HMAC signing key
   $table->boolean('slack_enabled')->default(false);
   $table->boolean('webhook_enabled')->default(false);
   ```

2. **Create `WebhookNotifier` service**:
   ```php
   class WebhookNotifier {
       public function sendSlack(string $webhookUrl, string $title, string $message, string $color = '#ff0000'): bool
       // Sends Slack Block Kit formatted message via Http::post()
       
       public function sendWebhook(string $url, string $secret, array $payload): bool
       // Sends JSON payload with HMAC-SHA256 signature in X-Signature header
   }
   ```

3. **Update notification classes** — Add `toSlack()` and `toWebhook()` methods to each notification:
   - `BlacklistAlert`
   - `DeliveryAlert` / `DeliveryIncidentAlert`
   - `DmarcAlert`
   - `ExpiryReminder`
   - `IncidentRaised`

4. **Update `via()` method** in each notification to conditionally include slack/webhook channels based on user prefs.

5. **Create custom notification channels**:
   - `App\Channels\SlackWebhookChannel`
   - `App\Channels\CustomWebhookChannel`

6. **Update notification settings UI** — Add fields for:
   - Slack webhook URL (with "Test" button)
   - Custom webhook URL (with "Test" button)
   - Toggle on/off per notification type

7. **Plan-gate** — Only allow for Premium+ users (method already exists).

---

## Task 7 — Differentiate Ultra Tier
**Priority:** P2
**Effort:** Variable (depends on features chosen)
**Files:**
- `app/Models/User.php`
- `config/plans.php`
- Various controllers depending on features

### Problem
Premium → Ultra only adds domain/monitor limits (10→50). No exclusive features justify the higher price.

### Recommended Ultra-Exclusive Features

#### 7a. API Access (3–5 days)
- Create `routes/api.php` with token-authenticated endpoints
- Endpoints: scan domain, get scan results, list domains, get blacklist status, get SPF analysis
- Use Laravel Sanctum for API tokens
- Add API token management to profile page
- Rate limit: 100 requests/hour for Ultra

#### 7b. Team / Multi-User Access (5–8 days)
- Add `teams` table and `team_user` pivot
- Allow Ultra users to invite team members
- Shared domain access within a team
- Role-based permissions (admin, viewer)

#### 7c. White-Label PDF Reports (2–3 days)
- Allow Ultra users to upload their logo
- Use custom logo in weekly PDF reports and evidence packs
- Custom color scheme option
- Remove "MXScan" branding from exported reports

#### 7d. Custom Webhook Integrations (included in Task 6)

#### 7e. Priority Scan Cadence (1 day)
- Allow Ultra users to set hourly scan cadence (currently minimum is daily)
- Add `'hourly'` option to schedule frequency

### Implementation
1. Add `canUseApi()`, `canUseTeams()`, `canUseWhiteLabel()` methods to `User.php`
2. Gate to `ultra` plan key only
3. Update pricing page to highlight Ultra-exclusive features

---

## Task 8 — Add DKIM Selector Lookup Tool
**Priority:** P2
**Effort:** 1–2 days
**Files:**
- `app/Http/Controllers/ToolsController.php` (or new dedicated controller)
- New: `resources/views/tools/dkim-lookup.blade.php`
- `app/Services/DkimVerifier.php` (reuse `fetchPublicKey()`)
- `routes/web.php`

### Problem
The `DkimVerifier` already has DNS-based DKIM key fetching logic but it's only used during delivery monitoring email analysis. A standalone DKIM lookup tool would be high-value and easy to build.

### Implementation Steps

1. **Add route**:
   ```php
   Route::get('/tools/dkim', [ToolsController::class, 'dkimLookup'])->name('tools.dkim');
   Route::post('/tools/dkim', [ToolsController::class, 'dkimLookupRun'])->name('tools.dkim.run');
   ```

2. **Create form view** — Input fields:
   - Domain (required)
   - Selector (optional — if blank, probe common selectors from `config('dkim.selectors')`)

3. **Controller logic**:
   ```php
   public function dkimLookupRun(Request $request)
   {
       $domain = $request->input('domain');
       $selector = $request->input('selector');
       
       $results = [];
       $selectors = $selector ? [$selector] : config('dkim.selectors', []);
       
       foreach ($selectors as $sel) {
           $dnsName = "{$sel}._domainkey.{$domain}";
           $records = dns_get_record($dnsName, DNS_TXT);
           
           if (!empty($records)) {
               foreach ($records as $rec) {
                   if (isset($rec['txt']) && str_contains($rec['txt'], 'p=')) {
                       $keyInfo = $this->parseDkimPublicKey($rec['txt']);
                       $results[] = [
                           'selector' => $sel,
                           'record' => $rec['txt'],
                           'key_type' => $keyInfo['type'],
                           'key_bits' => $keyInfo['bits'],
                           'status' => $keyInfo['bits'] >= 1024 ? 'ok' : 'weak',
                       ];
                   }
               }
           }
       }
       
       return view('tools.dkim-lookup', compact('domain', 'results', 'selector'));
   }
   ```

4. **Display results**: Table showing selector, key type (RSA/Ed25519), key size, and status badge (ok/weak/revoked).

5. **Optional**: Also make this available on the public scan page (Task 3) as a secondary tool.

---

## Task 9 — Parallelize Blacklist Checks
**Priority:** P3
**Effort:** 2–3 days
**Files:**
- `app/Services/BlacklistChecker.php`

### Problem
Blacklist checks query each IP against each RBL provider sequentially. With 6 enabled providers and potentially 3-4 IPs per domain, this can take 30+ seconds due to DNS timeouts.

### Implementation Steps

#### Option A — Use Laravel's `concurrency` (Laravel 11+)
```php
use Illuminate\Support\Facades\Concurrency;

public function checkDomain(Scan $scan, string $domain): array
{
    $ips = $this->getDomainIPs($domain);
    $providers = $this->getRblProviders();
    
    // Build tasks array
    $tasks = [];
    foreach ($ips as $ip) {
        foreach ($providers as $providerId => $provider) {
            $tasks["{$ip}_{$providerId}"] = fn() => $this->checkIPAgainstRBL($ip, $provider);
        }
    }
    
    // Run all checks concurrently
    $results = Concurrency::run($tasks);
    
    // Process results...
}
```

#### Option B — Use Process Forking with Promises (if not on Laravel 11)
Use `spatie/async` package:
```php
use Spatie\Async\Pool;

$pool = Pool::create()->concurrency(10)->timeout(10);

foreach ($ips as $ip) {
    foreach ($providers as $providerId => $provider) {
        $pool->add(function() use ($ip, $provider) {
            return $this->checkIPAgainstRBL($ip, $provider);
        })->then(function($result) use (&$results, $ip, $provider, $scan) {
            // Store result
        });
    }
}

$pool->wait();
```

#### Option C — Dispatch Individual Jobs (Simplest)
Dispatch each IP+provider check as a separate queued job, then aggregate when all complete. This is the most robust approach but requires a way to track completion (e.g., batch jobs with `Bus::batch()`).

### Recommendation
Option A if on Laravel 11+, otherwise Option C using `Bus::batch()` for reliability.

---

## Task 10 — Clean Up Repository
**Priority:** P3
**Effort:** 1 hour
**Files:**
- Root directory (28+ markdown files)
- `config/rbl.php` (dead providers)

### Implementation Steps

1. **Remove development documentation files** from root:
   ```bash
   # These are dev notes, not user-facing docs. Archive or delete:
   rm ARCHITECTURE.md
   rm AUTOMATION_RUN_NOW_IMPLEMENTATION.md
   rm BACKFILL_IMPLEMENTATION.md
   rm BLACKLIST_FEATURE.md
   rm CASE_SAFE_TOKEN_IMPLEMENTATION.md
   rm CONSOLIDATION_SUMMARY.md
   rm DELIVERY_AUTH_FINAL_FIX.md
   rm DELIVERY_AUTH_FORCE_COMPUTE.md
   rm DELIVERY_AUTH_OPCACHE_ISSUE.md
   rm DELIVERY_ENHANCEMENTS_FINAL.md
   rm DELIVERY_MONITORING_ENHANCEMENTS.md
   rm DELIVERY_MONITORING_FIXES.md
   rm DELIVERY_MONITOR_ACTION_ORIENTED_UI.md
   rm DELIVERY_MONITOR_ALL_FOLDERS_UPDATE.md
   rm DELIVERY_MONITOR_CPANEL_IMPLEMENTATION.md
   rm DELIVERY_MONITOR_FINAL_STATUS.md
   rm DELIVERY_MONITOR_REFACTOR_COMPLETE.md
   rm DELIVERY_MONITOR_VERIFICATION.sh
   rm DEPLOYMENT_SETUP.md
   rm DIAGNOSTIC_RESULTS.md
   rm EMAIL_AUTH_QUICK_START.md
   rm EMAIL_AUTH_RAW_MESSAGE_FIX.md
   rm EMAIL_AUTH_VERIFIER_IMPLEMENTATION.md
   rm EXPIRY_SYSTEM_SIMPLIFIED.md
   rm FINAL_IMPLEMENTATION_SUMMARY.md
   rm FINAL_SUCCESS_SUMMARY.md
   rm IMPLEMENTATION_COMPLETE_SUMMARY.md
   rm IMPLEMENTATION_SUCCESS.md
   rm IMPLEMENTATION_SUMMARY.md
   rm QUICK_REFERENCE.md
   rm QUICK_TEST_GUIDE.md
   rm RBL_OPTIMIZATION.md
   rm READY_TO_TEST.md
   rm REPORT.md
   rm SCHEDULE_RUN_NOW_IMPLEMENTATION.md
   rm STRING_NORMALIZATION_FIX.md
   rm SUBSCRIPTION_FIX_SUMMARY.md
   rm TEST_SUBSCRIPTION_SYSTEM.md
   rm WEBKLEX_IMPLEMENTATION_COMPLETE.md
   ```

2. **Remove dead RBL providers** from `config/rbl.php`:
   - Remove `njabl` — NJABL has been defunct since 2013
   - Remove `ahbl` — AHBL has been listing all IPs as 127.0.0.2 since 2015
   - Remove `dcc` — blacklist.woody.ch is unreliable
   - Consider removing `dnsrbl` (five-ten-sg) — rarely maintained

3. **Remove test files** (already gitignored but still on disk):
   ```bash
   rm test_auth_check.php
   rm test_expiry_email.php
   rm test_fi_expiry.php
   rm test_fi_whois_raw.php
   rm test_string_normalization.php
   rm test_webhook.php
   rm verify_auth_implementation.php
   rm composer-setup.php
   ```

4. **Clean up `.gitignore`** — The `*.md` / `!README.md` pattern already handles most docs. Ensure no stale entries remain.

---

## Summary Table

| # | Task | Priority | Effort | Impact |
|---|---|---|---|---|
| 1 | Implement/hide stub tools | P0 | 2–4 days | Trust & credibility |
| 2 | DKIM in DNS scan | P0 | 2–3 days | Core feature gap |
| 3 | Public scan page | P1 | 3–5 days | Lead gen & SEO |
| 4 | Fix DnsClient failures | P1 | 1–2 days | False positive bugs |
| 5 | Consolidate routes | P2 | 1–2 days | Maintenance |
| 6 | Slack/webhook notifications | P2 | 3–5 days | Monitoring completeness |
| 7 | Differentiate Ultra | P2 | Variable | Revenue |
| 8 | DKIM lookup tool | P2 | 1–2 days | User value |
| 9 | Parallelize blacklist | P3 | 2–3 days | Performance |
| 10 | Clean up repo | P3 | 1 hour | Code hygiene |

**Recommended execution order:** 10 → 4 → 1 → 2 → 8 → 3 → 5 → 6 → 7 → 9
