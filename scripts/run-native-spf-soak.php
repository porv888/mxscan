<?php

declare(strict_types=1);

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\Plan;
use App\Models\Scan;
use App\Models\Subscription;
use App\Models\User;
use App\Services\ScanRunner;
use App\Services\ScoreBreakdownService;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;

/** @var Application $app */
require __DIR__ . '/../vendor/autoload.php';
$app = require __DIR__ . '/../bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$soakStart = microtime(true);
$soakStartedAt = now()->toIso8601String();

        if (is_file(app_path('Domain/EmailSecurity/Checks/SpfAnalysisCheck.php'))) {
            fwrite(STDERR, "ABORT: legacy SpfAnalysisCheck still present\n");
            exit(1);
        }

$breakdown = new ScoreBreakdownService();
$reportPath = storage_path('app/native-spf-soak-report.json');
$logMarker = 'native-spf-soak-' . date('Ymd-His');

$approvedDomains = [
    ['host' => 'iana.org', 'category' => 'no_spf', 'min_spf' => null, 'max_spf' => null],
    ['host' => 'google.com', 'category' => 'google_workspace', 'min_spf' => 10, 'max_spf' => 20],
    ['host' => 'microsoft.com', 'category' => 'microsoft_365', 'min_spf' => 10, 'max_spf' => 20],
    ['host' => 'github.com', 'category' => 'nested_includes', 'min_spf' => 8, 'max_spf' => 20],
    ['host' => 'salesforce.com', 'category' => 'nested_includes', 'min_spf' => 8, 'max_spf' => 20],
    ['host' => 'amazon.com', 'category' => 'high_lookup', 'min_spf' => 0, 'max_spf' => 20],
    ['host' => 'facebook.com', 'category' => 'redirect', 'min_spf' => 8, 'max_spf' => 20],
    ['host' => 'linkedin.com', 'category' => 'nested_includes', 'min_spf' => 8, 'max_spf' => 20],
    ['host' => 'apple.com', 'category' => 'high_lookup', 'min_spf' => 0, 'max_spf' => 20],
    ['host' => 'stripe.com', 'category' => 'nested_includes', 'min_spf' => 8, 'max_spf' => 20],
    ['host' => 'spotify.com', 'category' => 'complex', 'min_spf' => 0, 'max_spf' => 20],
    ['host' => 'yahoo.com', 'category' => 'missing_dependency_risk', 'min_spf' => 0, 'max_spf' => 20],
];

$results = [
    'soak_started_at' => $soakStartedAt,
    'log_marker' => $logMarker,
    'spf_pipeline' => 'native-mandatory',
    'queue_default_initial' => config('queue.default'),
    'approved_domains' => array_column($approvedDomains, 'host'),
    'scans' => [],
    'counts_by_path' => [],
    'failures' => [],
    'stopped_early' => false,
    'stop_reason' => null,
];

function ensureSoakUser(): User
{
    $email = 'native-spf-soak@mxscan.internal';

    $user = User::query()->where('email', $email)->first();
    if ($user) {
        return $user;
    }

    $plan = Plan::query()->where('name', 'Premium')->first();
    if (!$plan) {
        Artisan::call('db:seed', ['--class' => 'PlanSeeder', '--force' => true]);
        $plan = Plan::query()->where('name', 'Premium')->firstOrFail();
    }

    $user = User::query()->create([
        'name' => 'Native SPF Soak',
        'email' => $email,
        'password' => Hash::make(str()->random(32)),
        'email_verified_at' => now(),
        'role' => 'user',
        'status' => 'active',
    ]);

    Subscription::query()->create([
        'user_id' => $user->id,
        'plan_id' => $plan->id,
        'status' => 'active',
        'started_at' => now(),
    ]);

    return $user;
}

function ensureDomain(User $user, string $host): Domain
{
    return Domain::query()->firstOrCreate(
        ['user_id' => $user->id, 'domain' => $host],
        ['environment' => 'prod', 'status' => 'active']
    );
}

function clearDomainCooldown(Domain $domain): void
{
    Cache::forget("scan:cooldown:domain:{$domain->id}");
}

function verifyScan(Scan $scan, Domain $domain, User $user, array $expect, ScoreBreakdownService $breakdown): array
{
    $errors = [];
    $scan = $scan->fresh();
    $domain = $domain->fresh();

    if ($scan->status !== 'finished') {
        return ['status' => $scan->status, 'errors' => ['scan not finished']];
    }

    $resultJson = is_array($scan->result_json) ? $scan->result_json : json_decode((string) $scan->result_json, true);
    $analysis = $resultJson['spf']['analysis'] ?? null;

    if (!is_array($analysis) || ($analysis['version'] ?? null) !== 'spf-native-v1') {
        $errors[] = 'missing spf-native-v1 analysis';
    }

    if (!is_string($analysis['protocol_status'] ?? null) || $analysis['protocol_status'] === '') {
        $errors[] = 'missing protocol_status';
    }

    if (!is_string($analysis['risk_status'] ?? null) || $analysis['risk_status'] === '') {
        $errors[] = 'missing risk_status';
    }

    $protocol = $analysis['protocol_status'] ?? null;
    if (in_array($protocol, ['valid', 'permerror', 'partially_evaluated'], true)
        && !is_string($analysis['terminal_policy'] ?? null)) {
        $errors[] = 'missing terminal_policy';
    }

    $spfRow = $breakdown->findRow($resultJson['dns']['score_breakdown'] ?? [], 'spf');
    $spfEarned = $spfRow['earned'] ?? null;
    $totalEarned = $breakdown->totalEarned($resultJson['dns']['score_breakdown'] ?? []);

    if ($spfEarned === null) {
        $errors[] = 'missing spf score row';
    }

    if ($totalEarned !== $scan->score) {
        $errors[] = "score invariant mismatch total={$scan->score} breakdown={$totalEarned}";
    }

    if ($expect['min_spf'] !== null && $spfEarned !== null && $spfEarned < $expect['min_spf']) {
        $errors[] = "spf earned {$spfEarned} below min {$expect['min_spf']}";
    }

    if ($expect['max_spf'] !== null && $spfEarned !== null && $spfEarned > $expect['max_spf']) {
        $errors[] = "spf earned {$spfEarned} above max {$expect['max_spf']}";
    }

    $recommendations = is_array($scan->recommendations_json) ? $scan->recommendations_json : [];
    $semanticKeys = array_values(array_filter(array_map(
        fn ($item) => is_array($item) ? ($item['semantic_key'] ?? $item['key'] ?? null) : null,
        $recommendations
    )));
    if (count($semanticKeys) !== count(array_unique($semanticKeys))) {
        $errors[] = 'duplicate recommendation semantic keys';
    }

    Auth::login($user);
    try {
        $report = app(ScanReportFactoryInterface::class)->build($scan->fresh(), $domain);
        $cards = $report->toArray()['statusCards'] ?? null;
        if (!is_array($cards) || !is_array($cards['spf'] ?? null)) {
            $errors[] = 'report missing spf status card';
        }
    } catch (Throwable $e) {
        $errors[] = 'report render failed: ' . $e->getMessage();
    }

    return [
        'status' => $scan->status,
        'errors' => $errors,
        'protocol_status' => $analysis['protocol_status'] ?? null,
        'risk_status' => $analysis['risk_status'] ?? null,
        'terminal_policy' => $analysis['terminal_policy'] ?? null,
        'spf_earned' => $spfEarned,
        'score' => $scan->score,
        'duration_ms' => $scan->duration_ms,
        'lookup_count' => $analysis['lookup_count'] ?? null,
    ];
}

function stopSoak(array &$results, string $reason): void
{
    $results['stopped_early'] = true;
    $results['stop_reason'] = $reason;
}

function recordScan(array &$results, string $path, Domain $domain, array $expect, ?Scan $scan, array $verification, float $started): void
{
    $results['counts_by_path'][$path] = ($results['counts_by_path'][$path] ?? 0) + 1;
    $entry = [
        'path' => $path,
        'category' => $expect['category'],
        'domain' => $domain->domain,
        'scan_id' => $scan?->id,
        'elapsed_ms' => (int) round((microtime(true) - $started) * 1000),
        'verification' => $verification,
    ];
    $results['scans'][] = $entry;

    if (($verification['errors'] ?? []) !== []) {
        $results['failures'][] = $entry;
    }
}

$user = ensureSoakUser();
$domainModels = [];
foreach ($approvedDomains as $spec) {
    $domainModels[$spec['host']] = ['model' => ensureDomain($user, $spec['host']), 'spec' => $spec];
}

$scanPlan = [];
foreach ($approvedDomains as $spec) {
    $host = $spec['host'];
    $scanPlan[] = ['path' => 'ui_queued_full', 'host' => $host];
    $scanPlan[] = ['path' => 'ui_queued_spf', 'host' => $host];
    $scanPlan[] = ['path' => 'ui_sync_full', 'host' => $host];
    $scanPlan[] = ['path' => 'ui_sync_spf', 'host' => $host];
    $scanPlan[] = ['path' => 'scan_runner_full', 'host' => $host];
}

while (count($scanPlan) < 52) {
    $scanPlan[] = ['path' => 'queued_job_spf', 'host' => $approvedDomains[count($scanPlan) % count($approvedDomains)]['host']];
}

$controller = app(App\Http\Controllers\ScanController::class);
$runner = app(ScanRunner::class);

echo "Starting native SPF soak ({$logMarker}) with " . count($scanPlan) . " planned scans\n";
echo "spf_pipeline=native-mandatory\n";

foreach ($scanPlan as $index => $item) {
    if ($results['stopped_early']) {
        break;
    }

    $path = $item['path'];
    $host = $item['host'];
    $domain = $domainModels[$host]['model'];
    $expect = $domainModels[$host]['spec'];
    clearDomainCooldown($domain);

    Auth::login($user);
    $started = microtime(true);
    $scan = null;

    try {
        if ($path === 'ui_queued_full') {
            config(['queue.default' => 'sync']);
            $request = Request::create("/domains/{$domain->id}/scan", 'POST');
            $request->setUserResolver(fn () => $user);
            $response = $controller->run($request, $domain);
            usleep(500_000);
            $scan = Scan::query()->where('domain_id', $domain->id)->latest('started_at')->first();
        } elseif ($path === 'ui_queued_spf') {
            config(['queue.default' => 'sync']);
            $request = Request::create("/domains/{$domain->id}/scan/spf", 'POST');
            $request->setUserResolver(fn () => $user);
            $controller->runSpf($request, $domain);
            usleep(500_000);
            $scan = Scan::query()->where('domain_id', $domain->id)->latest('started_at')->first();
        } elseif ($path === 'ui_sync_full') {
            $request = Request::create("/domains/{$domain->id}/scan-now", 'POST', ['mode' => 'full']);
            $request->headers->set('Accept', 'application/json');
            $request->setUserResolver(fn () => $user);
            $response = $controller->runSync($request, $domain);
            $payload = json_decode($response->getContent(), true);
            $scan = isset($payload['scan_id']) ? Scan::query()->find($payload['scan_id']) : null;
        } elseif ($path === 'ui_sync_spf') {
            $request = Request::create("/domains/{$domain->id}/scan-now", 'POST', ['mode' => 'spf']);
            $request->headers->set('Accept', 'application/json');
            $request->setUserResolver(fn () => $user);
            $response = $controller->runSync($request, $domain);
            $payload = json_decode($response->getContent(), true);
            $scan = isset($payload['scan_id']) ? Scan::query()->find($payload['scan_id']) : null;
        } elseif ($path === 'scan_runner_full') {
            $scan = $runner->runSync($domain, ['dns' => true, 'spf' => true, 'blacklist' => false, 'monitoring' => false]);
        } elseif ($path === 'queued_job_spf') {
            config(['queue.default' => 'database']);
            if (is_file(app_path('Domain/EmailSecurity/Checks/SpfAnalysisCheck.php'))) {
                stopSoak($results, 'legacy SpfAnalysisCheck still present');
                break;
            }
            $scanRecord = Scan::query()->create([
                'domain_id' => $domain->id,
                'user_id' => $domain->user_id,
                'type' => 'spf',
                'status' => 'running',
                'progress_pct' => 0,
                'started_at' => now(),
            ]);
            RunFullScan::dispatch($domain->id, [
                'dns' => false,
                'spf' => true,
                'blacklist' => false,
                'scan_id' => $scanRecord->id,
            ]);
            Artisan::call('queue:work', [
                '--once' => true,
                '--timeout' => 300,
                '--tries' => 1,
            ]);
            $scan = $scanRecord->fresh();
            config(['queue.default' => 'sync']);
        }
    } catch (Throwable $e) {
        $verification = ['status' => 'exception', 'errors' => ['exception: ' . $e->getMessage()]];
        recordScan($results, $path, $domain, $expect, $scan, $verification, $started);
        if (str_contains($e->getMessage(), 'Score invariant')) {
            stopSoak($results, $e->getMessage());
            break;
        }
        continue;
    }

    if (!$scan) {
        recordScan($results, $path, $domain, $expect, null, ['status' => 'missing', 'errors' => ['scan record not found']], $started);
        continue;
    }

    $verification = verifyScan($scan, $domain, $user, $expect, $breakdown);
    recordScan($results, $path, $domain, $expect, $scan, $verification, $started);

    if ($verification['errors'] !== []) {
        $critical = false;
        foreach ($verification['errors'] as $error) {
            if (str_contains($error, 'score invariant')
                || (str_contains($error, 'below min') && in_array($expect['category'], ['google_workspace', 'microsoft_365'], true))
                || str_contains($error, 'report render failed')) {
                $critical = true;
                break;
            }
        }
        if ($critical) {
            stopSoak($results, implode('; ', $verification['errors']));
            break;
        }
    }

    if (($index + 1) % 5 === 0) {
        echo 'Completed ' . ($index + 1) . '/' . count($scanPlan) . PHP_EOL;
        usleep(2_000_000);
    } else {
        usleep(1_000_000);
    }
}

$soakEnd = now()->toIso8601String();
$completed = array_values(array_filter($results['scans'], fn ($s) => ($s['verification']['status'] ?? null) === 'finished'));
$failed = array_values(array_filter($results['scans'], fn ($s) => ($s['verification']['errors'] ?? []) !== []));

$protocolCounts = [];
$riskCounts = [];
$spfScoreCounts = [];
$temperror = 0;
$partial = 0;
$lookupLimit = 0;
$durations = [];

foreach ($results['scans'] as $entry) {
    $v = $entry['verification'];
    if ($p = $v['protocol_status'] ?? null) {
        $protocolCounts[$p] = ($protocolCounts[$p] ?? 0) + 1;
    }
    if ($r = $v['risk_status'] ?? null) {
        $riskCounts[$r] = ($riskCounts[$r] ?? 0) + 1;
    }
    if (($e = $v['spf_earned'] ?? null) !== null) {
        $spfScoreCounts[(string) $e] = ($spfScoreCounts[(string) $e] ?? 0) + 1;
    }
    if (($v['protocol_status'] ?? null) === 'temperror') {
        $temperror++;
    }
    if (($v['protocol_status'] ?? null) === 'partially_evaluated') {
        $partial++;
    }
    if (($v['duration_ms'] ?? null) !== null) {
        $durations[] = (int) $v['duration_ms'];
    }
}

$uiPaths = ['ui_queued_full', 'ui_queued_spf', 'ui_sync_full', 'ui_sync_spf'];
$uiCount = 0;
foreach ($uiPaths as $p) {
    $uiCount += $results['counts_by_path'][$p] ?? 0;
}

$logFiles = glob(storage_path('logs/laravel-*.log')) ?: [];
$logChecks = [
    'score_invariant' => 0,
    'spf_check_exceptions' => 0,
    'resolver_timeouts' => 0,
    'persistence_errors' => 0,
    'report_errors' => 0,
];
foreach ($logFiles as $file) {
    $contents = (string) @file_get_contents($file);
    $logChecks['score_invariant'] += substr_count($contents, 'Score invariant violated');
    $logChecks['spf_check_exceptions'] += preg_match_all('/SpfCheck|EmailSecurityScanService.*(?:Exception|failed)/i', $contents) ?: 0;
    $logChecks['resolver_timeouts'] += substr_count(strtolower($contents), 'timeout');
    $logChecks['persistence_errors'] += substr_count(strtolower($contents), 'savefinished');
    $logChecks['report_errors'] += substr_count(strtolower($contents), 'report');
}

$summary = [
    'soak_started_at' => $soakStartedAt,
    'soak_ended_at' => $soakEnd,
    'soak_duration_seconds' => (int) round(microtime(true) - $soakStart),
    'total_scans_attempted' => count($results['scans']),
    'completed_scans' => count($completed),
    'failed_scans' => count($failed),
    'success_rate_pct' => count($results['scans']) > 0 ? round(100 * (count($results['scans']) - count($failed)) / count($results['scans']), 2) : 0,
    'ui_triggered_scans' => $uiCount,
    'counts_by_path' => $results['counts_by_path'],
    'duration_ms_avg' => $durations !== [] ? (int) round(array_sum($durations) / count($durations)) : null,
    'duration_ms_max' => $durations !== [] ? max($durations) : null,
    'protocol_status_distribution' => $protocolCounts,
    'risk_status_distribution' => $riskCounts,
    'spf_score_distribution' => $spfScoreCounts,
    'temperror_count' => $temperror,
    'partially_evaluated_count' => $partial,
    'lookup_limit_errors' => $lookupLimit,
    'log_checks' => $logChecks,
    'stopped_early' => $results['stopped_early'],
    'stop_reason' => $results['stop_reason'],
    'failures' => $results['failures'],
];

$results['summary'] = $summary;
file_put_contents($reportPath, json_encode($results, JSON_PRETTY_PRINT));

echo PHP_EOL . 'Soak complete. Report: ' . $reportPath . PHP_EOL;
echo json_encode($summary, JSON_PRETTY_PRINT) . PHP_EOL;

exit($results['stopped_early'] || count($failed) > 0 ? 1 : 0);
