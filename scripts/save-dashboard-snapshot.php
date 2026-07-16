<?php

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Http\Controllers\DashboardController;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Auth;

require dirname(__DIR__) . '/vendor/autoload.php';
$app = require dirname(__DIR__) . '/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$domain = Domain::query()->where('domain', 'mxscan.me')->firstOrFail();
Auth::login($domain->user);

$label = preg_replace('/[^a-z0-9_-]/i', '', (string) env('DASHBOARD_SNAPSHOT_LABEL', 'after')) ?: 'after';
$view = app(DashboardController::class)->index();
$html = $view->render();

$document = new DOMDocument();
libxml_use_internal_errors(true);
$document->loadHTML('<?xml encoding="utf-8" ?>' . $html);
libxml_clear_errors();
$main = $document->getElementsByTagName('main')->item(0);
$dashboardHtml = $main ? $document->saveHTML($main) : $html;
$dashboardHtml = str_replace(' x-cloak', '', $dashboardHtml);

$inlineCss = file_get_contents(public_path('css/tailwind.css'))
    . "\n" . file_get_contents(public_path('css/mx-ui.css'));
$snapshot = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MXScan dashboard — {$label}</title>
<style>{$inlineCss}</style>
<style>[x-cloak]{display:none!important} body{margin:0;background:#f9fafb;}</style>
</head>
<body>{$dashboardHtml}</body>
</html>
HTML;

$latestScan = Scan::query()
    ->where('user_id', $domain->user_id)
    ->where('status', 'finished')
    ->with('domain')
    ->latest('finished_at')
    ->latest('id')
    ->first();
$report = $latestScan
    ? app(ScanReportFactoryInterface::class)->build($latestScan, $latestScan->domain)->toArray()
    : [];
$viewData = $view->getData();

$payload = [
    'latest_scan' => $latestScan ? [
        'id' => (string) $latestScan->id,
        'domain_id' => $latestScan->domain_id,
        'domain' => $latestScan->domain?->domain,
        'score' => $latestScan->score,
        'finished_at' => $latestScan->finished_at?->toIso8601String(),
    ] : null,
    'legacy_domain_score_last' => $latestScan?->domain?->score_last,
    'authoritative_dashboard' => $viewData['dashboardHero'] ?? null,
    'recommendations' => isset($viewData['dashboardRecommendations'])
        ? $viewData['dashboardRecommendations']->values()->all()
        : [],
    'source_recommendations' => $report['recommendations'] ?? [],
    'metrics' => $viewData['dashboardMetrics'] ?? [],
    'score_history' => $viewData['dashboardScoreHistory'] ?? [],
];

$dir = storage_path('app/dashboard-screenshots');
if (!is_dir($dir)) {
    mkdir($dir, 0775, true);
}

file_put_contents($dir . "/mxscan-dashboard-{$label}.html", $snapshot);
file_put_contents(
    $dir . "/mxscan-dashboard-view-model-{$label}.json",
    json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n",
);

echo "Saved {$label} dashboard and payload snapshots to {$dir}\n";
