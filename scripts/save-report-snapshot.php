<?php

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

require __DIR__ . '/../vendor/autoload.php';
$app = require __DIR__ . '/../bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

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
$viewData['dmarcStatus'] = null;
$viewData['scoreDeductions'] = [];

$html = view('scans.show', $viewData)->render();

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
<style>[x-cloak]{display:none!important} body{margin:0;background:#f9fafb;}</style>
</head>
<body>{$bodyHtml}</body>
</html>
HTML;
};

$desktop = $wrap(
    'mxscan.me report — desktop after',
    'width=device-width, initial-scale=1',
    '<div style="max-width:1320px;margin:0 auto;padding:24px;">' . $html . '</div>',
);

$mobile = $wrap(
    'mxscan.me report — mobile after',
    'width=390, initial-scale=1',
    '<div style="width:390px;padding:12px;">' . $html . '</div>',
);

file_put_contents($dir . '/mxscan-me-report-after-desktop.html', $desktop);
file_put_contents($dir . '/mxscan-me-report-after-mobile.html', $mobile);

echo "Saved snapshots to {$dir}\n";
