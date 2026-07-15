<?php

declare(strict_types=1);

use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;

/** @var Application $app */
require __DIR__ . '/../vendor/autoload.php';
$app = require __DIR__ . '/../bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

/** @var EmailSecurityScanService $scanService */
$scanService = $app->make(EmailSecurityScanService::class);

$domains = [
    'mxscan.me' => 'normal',
    'zend2.com' => 'bad_or_incomplete',
];

$failures = [];
$results = [];

foreach ($domains as $host => $expectation) {
    fwrite(STDOUT, "=== Scanning {$host} (expected: {$expectation}) ===\n");

    $domain = new Domain(['domain' => $host]);
    $scan = new Scan(['status' => 'running']);
    $options = ScanOptionsDTO::fromArray([
        'dns' => true,
        'spf' => true,
        'blacklist' => false,
    ]);

    try {
        $execution = $scanService->execute($domain, $scan, $options, microtime(true));
        $score = (int) ($execution->score ?? 0);
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        $possible = array_sum(array_column($breakdown, 'possible'));
        $earned = array_sum(array_column($breakdown, 'earned'));

        $rowSummary = [];
        foreach ($breakdown as $row) {
            $rowSummary[$row['key']] = [
                'earned' => $row['earned'] ?? 0,
                'possible' => $row['possible'] ?? 0,
            ];
        }

        $nativeVersions = [];
        $nativeKeyMap = [
            'spf' => 'spf',
            'dmarc' => 'dmarc',
            'dkim' => 'dkim',
            'mx' => 'mx',
            'mtasts' => 'mta_sts',
            'tlsrpt' => 'tls_rpt',
            'bimi' => 'bimi',
        ];
        foreach ($nativeKeyMap as $label => $jsonKey) {
            $version = $execution->resultJson[$jsonKey]['analysis']['version'] ?? null;
            if ($version !== null) {
                $nativeVersions[$label] = $version;
            }
        }

        $results[$host] = [
            'expectation' => $expectation,
            'score' => $score,
            'possible_sum' => $possible,
            'earned_sum' => $earned,
            'breakdown' => $rowSummary,
            'native_versions' => $nativeVersions,
        ];

        fwrite(STDOUT, json_encode($results[$host], JSON_PRETTY_PRINT) . "\n\n");

        if ($possible !== 100) {
            $failures[] = "{$host}: sum(possible)={$possible}, expected 100";
        }
        if ($earned !== $score) {
            $failures[] = "{$host}: sum(earned)={$earned} != score={$score}";
        }
        if ($score < 0 || $score > 100) {
            $failures[] = "{$host}: score={$score} out of range [0,100]";
        }

        $requiredNative = ['spf', 'dmarc', 'dkim', 'mx', 'mtasts', 'tlsrpt'];
        foreach ($requiredNative as $key) {
            if (!isset($nativeVersions[$key])) {
                $failures[] = "{$host}: missing native analysis for {$key}";
            }
        }

        if ($host === 'mxscan.me' && $score < 50) {
            $failures[] = "{$host}: expected working domain with score >= 50, got {$score}";
        }
        if ($host === 'zend2.com' && $score > 90) {
            $failures[] = "{$host}: expected bad/incomplete config with score <= 90, got {$score}";
        }
    } catch (Throwable $e) {
        $failures[] = "{$host}: exception: " . $e->getMessage();
        fwrite(STDERR, "ERROR: " . $e->getMessage() . "\n");
    }
}

if ($failures !== []) {
    fwrite(STDERR, "SMOKE FAILURES:\n" . implode("\n", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "SMOKE OK\n");
exit(0);
