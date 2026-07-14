<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\ScanReport\ScanRecommendationService;
use App\Services\ScanReport\ScanReportStatusMapper;
use App\View\Presenters\ScanReportPresenter;
use Tests\TestCase;

class ScanReportLayoutTest extends TestCase
{
    protected function sampleDomain(): Domain
    {
        $domain = new Domain(['domain' => 'mxscan.me']);
        $domain->id = 42;

        return $domain;
    }

    protected function sampleScan(): Scan
    {
        $scan = new Scan([
            'status' => 'finished',
            'score' => 70,
            'finished_at' => now(),
        ]);
        $scan->id = 99;

        return $scan;
    }

    protected function baseViewData(): array
    {
        $domain = $this->sampleDomain();
        $records = [
            'MX' => ['status' => 'found', 'data' => [['pri' => 10, 'target' => 'mail.mxscan.me', 'ttl' => 3600]]],
            'SPF' => ['status' => 'missing'],
            'DKIM' => ['status' => 'found', 'data' => [['selector' => 'default', 'record' => 'v=DKIM1; p=abc']]],
            'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=quarantine'],
            'TLS-RPT' => ['status' => 'found', 'data' => 'v=TLSRPTv1; rua=mailto:tls@mxscan.me'],
            'MTA-STS' => ['status' => 'missing'],
            'BIMI' => ['status' => 'missing'],
        ];
        $resultJson = [
            'dns' => ['records' => $records],
            'spf' => ['lookups' => null, 'valid' => true],
            'blacklist' => ['total_checks' => 6, 'listed_count' => 0],
        ];
        $mapper = new ScanReportStatusMapper();
        $statusCards = $mapper->buildStatusCards($resultJson, $records, 70);
        $recommendations = (new ScanRecommendationService($mapper))->build($domain, $resultJson, $records);

        return [
            'scan' => $this->sampleScan(),
            'domain' => $domain,
            'enabled' => ['dns' => true, 'spf' => true, 'blacklist' => true, 'delivery' => false],
            'scoreDelta' => null,
            'statusCards' => $statusCards,
            'records' => $records,
            'spfLookupCount' => null,
            'spfMax' => 10,
            'dmarcStatus' => null,
            'dmarcPolicy' => 'quarantine',
            'dmarcAligned' => false,
            'recommendations' => $recommendations,
            'allClear' => ['state' => 'needs_fixes', 'message' => null],
            'scoreBreakdown' => [
                ['key' => 'mx', 'label' => 'MX', 'earned' => 15, 'possible' => 15, 'status' => 'ok'],
                ['key' => 'spf', 'label' => 'SPF', 'earned' => 0, 'possible' => 20, 'status' => 'missing'],
            ],
            'scoreTrend' => ['labels' => ['Jul 1'], 'scores' => [70]],
            'blacklistHits' => 0,
            'blacklistTotal' => 6,
            'blacklistRows' => collect(),
            'domainDays' => 120,
            'sslDays' => 90,
            'cadence' => 'weekly',
            'incidents' => collect(),
            'deliveries' => collect(),
        ];
    }

    protected function actingUser(): User
    {
        $user = new User(['timezone' => 'UTC']);
        $user->id = 1;

        return $user;
    }

    public function test_report_page_does_not_render_legacy_kpi_grid(): void
    {
        $this->actingAs($this->actingUser());
        $html = view('scans.show', $this->baseViewData())->render();

        $this->assertStringNotContainsString('_kpi-cards', $html);
        $this->assertStringNotContainsString('Email Security Score (30 days)', $html);
        $this->assertStringNotContainsString('Domain Renewal', $html);
        $this->assertStringNotContainsString('lg:col-span-2', $html);
    }

    public function test_report_page_renders_new_hero_and_sections(): void
    {
        $this->actingAs($this->actingUser());
        $html = view('scans.show', $this->baseViewData())->render();

        $this->assertStringContainsString('mxscan.me', $html);
        $this->assertStringContainsString('Email security report', $html);
        $this->assertStringContainsString('What to fix', $html);
        $this->assertStringContainsString('Score breakdown', $html);
        $this->assertStringContainsString('Technical checks', $html);
        $this->assertStringContainsString('Score history', $html);
        $this->assertStringContainsString('max-w-[1320px]', $html);
    }

    public function test_single_scan_history_shows_empty_state_not_chart(): void
    {
        $this->actingAs($this->actingUser());
        $html = view('scans.show', $this->baseViewData())->render();

        $this->assertStringContainsString('Your trend will appear after another completed scan', $html);
        $this->assertStringNotContainsString('id="reportScoreTrend"', $html);
    }

    public function test_presenter_primary_finding_uses_first_recommendation(): void
    {
        $data = $this->baseViewData();
        $presenter = new ScanReportPresenter(
            domain: $data['domain'],
            score: 70,
            scoreDelta: null,
            statusCards: $data['statusCards'],
            recommendations: $data['recommendations'],
            allClear: $data['allClear'],
            scoreBreakdown: $data['scoreBreakdown'],
            scoreTrend: $data['scoreTrend'],
        );

        $finding = $presenter->primaryFinding();
        $this->assertNotNull($finding);
        $this->assertStringContainsString('SPF', $finding['title']);
    }
}
