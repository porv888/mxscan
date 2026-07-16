<?php

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

require __DIR__ . '/../vendor/autoload.php';
$app = require __DIR__ . '/../bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

if ((string) env('SCREENSHOT_EPHEMERAL', '') === '1') {
    Illuminate\Support\Facades\Artisan::call('migrate:fresh', ['--force' => true]);
}

$user = User::factory()->create();
Auth::login($user);

$domain = Domain::factory()->create([
    'user_id' => $user->id,
    'domain' => 'mxscan.me',
]);

$resultJson = json_decode(
    file_get_contents(base_path('tests/Fixtures/EmailSecurity/mxscan-me-scan-result.json')),
    true,
    512,
    JSON_THROW_ON_ERROR,
);

$scan = Scan::factory()->create([
    'domain_id' => $domain->id,
    'user_id' => $user->id,
    'type' => 'full',
    'status' => 'finished',
    'score' => 64,
    'result_json' => $resultJson,
]);

$viewData = app(ScanReportFactoryInterface::class)->build($scan, $domain)->toArray();
$viewData['scan'] = $scan;
$viewData['resultData'] = $resultJson;
$viewData['enabled'] = ['dns' => true, 'spf' => true, 'blacklist' => true, 'delivery' => false];
$viewData['blacklistRows'] = collect();
$viewData['incidents'] = collect();
$viewData['deliveries'] = collect();
$viewData['cadence'] = 'off';
$viewData['scoreDelta'] = null;
$viewData['hasDns'] = true;
$viewData['hasSpf'] = true;
$viewData['hasBlacklist'] = true;
$viewData['isFirstFinishedScan'] = true;
$viewData['snapshot'] = null;
$viewData['lastSnapshot'] = null;
$viewData['spfSuggestion'] = null;
$viewData['tlsrptOk'] = false;
$viewData['mtastsOk'] = false;
$viewData['bimiHasData'] = false;
$viewData['bimiOk'] = false;
$viewData['domainDays'] = 120;
$viewData['sslDays'] = null;
$viewData['scoreDeductions'] = [];

$label = preg_replace('/[^a-z0-9_-]/i', '', (string) env('REPORT_SNAPSHOT_LABEL', 'after')) ?: 'after';
$html = view('scans.show', $viewData)->render();
$document = new DOMDocument();
libxml_use_internal_errors(true);
$document->loadHTML('<?xml encoding="utf-8" ?>' . $html);
libxml_clear_errors();
$main = $document->getElementsByTagName('main')->item(0);
$reportHtml = $main ? $document->saveHTML($main) : $html;
$reportHtml = str_replace(' x-cloak', '', $reportHtml);

$dir = storage_path('app/report-screenshots');
if (!is_dir($dir)) {
    mkdir($dir, 0775, true);
}

$inlineCss = file_get_contents(public_path('css/tailwind.css'))
    . "\n" . file_get_contents(public_path('css/mx-ui.css'));

$wrap = function (string $title, string $viewport, string $bodyHtml) use ($inlineCss): string {
    return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="{$viewport}">
<title>{$title}</title>
<style>{$inlineCss}</style>
<style>[x-cloak]{display:none!important} .mx-dns-provider-steps{display:none!important} body{margin:0;background:#f9fafb;}</style>
</head>
<body>{$bodyHtml}</body>
</html>
HTML;
};

$snapshot = $wrap(
    "mxscan.me report — {$label}",
    'width=device-width, initial-scale=1',
    $reportHtml,
);

$payload = [
    'score' => $viewData['score'] ?? null,
    'statusCards' => $viewData['statusCards'] ?? [],
    'recommendations' => $viewData['recommendations'] ?? [],
    'allClear' => $viewData['allClear'] ?? [],
    'scoreBreakdown' => $viewData['scoreBreakdown'] ?? [],
    'technicalRemediation' => $viewData['technicalRemediation'] ?? [],
    'dmarcPolicy' => $viewData['dmarcPolicy'] ?? null,
    'dmarcAlignmentVerification' => $viewData['dmarcAlignmentVerification'] ?? null,
];

file_put_contents($dir . "/mxscan-me-report-{$label}.html", $snapshot);
file_put_contents(
    $dir . "/mxscan-me-view-model-{$label}.json",
    json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n",
);

echo "Saved {$label} report and payload snapshots to {$dir}\n";
