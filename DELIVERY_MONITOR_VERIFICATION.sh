#!/bin/bash
# Delivery Monitor Verification Commands
# Run these to verify the refactored pipeline is working correctly

echo "=========================================="
echo "Delivery Monitor Pipeline Verification"
echo "=========================================="
echo ""

# 0) Clear caches
echo "1. Clearing caches..."
php artisan cache:clear && php artisan config:clear
echo ""

# 1) Run collector (should be clean, no array->string errors)
echo "2. Running collector (verbose)..."
php artisan monitor:collect -vv
echo ""

# 2) Check database state
echo "3. Checking database state..."
php artisan tinker --execute="
echo 'Total checks: ' . \App\Models\DeliveryCheck::count() . PHP_EOL;
echo 'Null auth_meta: ' . \App\Models\DeliveryCheck::whereNull('auth_meta')->count() . PHP_EOL;
\$c = \App\Models\DeliveryCheck::latest()->first();
if (\$c) {
    echo 'Latest check ID: ' . \$c->id . PHP_EOL;
    echo '  SPF: ' . (\$c->spf_pass === null ? 'none' : (\$c->spf_pass ? 'pass' : 'fail')) . PHP_EOL;
    echo '  DKIM: ' . (\$c->dkim_pass === null ? 'none' : (\$c->dkim_pass ? 'pass' : 'fail')) . PHP_EOL;
    echo '  DMARC: ' . (\$c->dmarc_pass === null ? 'none' : (\$c->dmarc_pass ? 'pass' : 'fail')) . PHP_EOL;
    echo '  Verdict: ' . \$c->verdict . PHP_EOL;
    echo '  TTI: ' . (\$c->tti_ms ? round(\$c->tti_ms / 1000, 2) . 's' : 'N/A') . PHP_EOL;
    echo '  MX Host: ' . (\$c->mx_host ?: 'N/A') . PHP_EOL;
    echo '  MX IP: ' . (\$c->mx_ip ?: 'N/A') . PHP_EOL;
    echo '  Auth meta keys: ' . (is_array(\$c->auth_meta) ? count(\$c->auth_meta) : 0) . PHP_EOL;
}
"
echo ""

# 3) Check for specific monitor
echo "4. Checking monitor status..."
php artisan tinker --execute="
\$m = \App\Models\DeliveryMonitor::first();
if (\$m) {
    echo 'Monitor ID: ' . \$m->id . PHP_EOL;
    echo 'Token: ' . \$m->token . PHP_EOL;
    echo 'Email: monitor+' . \$m->token . '@mxscan.me' . PHP_EOL;
    echo 'Folder: INBOX.' . \$m->token . PHP_EOL;
    echo 'Checks: ' . \$m->checks()->count() . PHP_EOL;
    echo 'Last check: ' . (\$m->last_check_at ?: 'Never') . PHP_EOL;
}
"
echo ""

# 4) Show sample check details
echo "5. Sample check with auth details..."
php artisan tinker --execute="
\$c = \App\Models\DeliveryCheck::whereNotNull('auth_meta')->latest()->first();
if (\$c) {
    echo 'Check ID: ' . \$c->id . PHP_EOL;
    echo 'From: ' . \$c->from_addr . PHP_EOL;
    echo 'To: ' . \$c->to_addr . PHP_EOL;
    echo 'Subject: ' . \$c->subject . PHP_EOL;
    echo 'Received: ' . \$c->received_at . PHP_EOL;
    echo '---' . PHP_EOL;
    echo 'SPF: ' . (\$c->spf_pass === null ? 'none' : (\$c->spf_pass ? 'PASS' : 'FAIL')) . PHP_EOL;
    echo 'DKIM: ' . (\$c->dkim_pass === null ? 'none' : (\$c->dkim_pass ? 'PASS' : 'FAIL')) . PHP_EOL;
    echo 'DMARC: ' . (\$c->dmarc_pass === null ? 'none' : (\$c->dmarc_pass ? 'PASS' : 'FAIL')) . PHP_EOL;
    echo 'Verdict: ' . strtoupper(\$c->verdict) . PHP_EOL;
    echo '---' . PHP_EOL;
    if (is_array(\$c->auth_meta)) {
        echo 'Auth meta structure:' . PHP_EOL;
        foreach (array_keys(\$c->auth_meta) as \$key) {
            echo '  - ' . \$key . PHP_EOL;
        }
    }
}
"
echo ""

echo "=========================================="
echo "Verification Complete!"
echo "=========================================="
echo ""
echo "Expected results:"
echo "  ✓ Collector runs without 'Array to string conversion' errors"
echo "  ✓ Null auth_meta count should be 0 (after backfill)"
echo "  ✓ Latest check shows proper SPF/DKIM/DMARC values"
echo "  ✓ Auth meta contains: spf, dkim, dmarc, metrics, analysis, details"
echo ""
echo "If any checks have null auth_meta, run:"
echo "  php artisan delivery:backfill-auth 200"
echo ""
