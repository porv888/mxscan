<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Services\Dmarc\DmarcStatusService;
use App\Services\ScanReport\ScanReportStatusMapper;
use App\View\Presenters\DnsSectionPresenter;
use Tests\TestCase;

class DnsSectionLayoutTest extends TestCase
{
    protected function sampleDomain(): Domain
    {
        $domain = new Domain([
            'domain' => 'example.test',
        ]);
        $domain->id = 1;

        return $domain;
    }

    protected function baseRecords(array $overrides = []): array
    {
        return array_merge([
            'MX' => ['status' => 'found', 'data' => [['pri' => 10, 'target' => 'mail.example.test', 'ttl' => 3600]]],
            'SPF' => ['status' => 'missing'],
            'DKIM' => ['status' => 'found', 'data' => [['selector' => 'google', 'record' => 'v=DKIM1; p=abc']]],
            'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
            'TLS-RPT' => ['status' => 'missing'],
            'MTA-STS' => ['status' => 'missing'],
            'BIMI' => ['status' => 'missing'],
        ], $overrides);
    }

    protected function sampleMxInfo(array $overrides = []): array
    {
        return array_replace_recursive([
            'status' => 'ok',
            'protocol_status' => 'valid',
            'analysis' => [
                'version' => 'mx-native-v1',
                'protocol_status' => 'valid',
                'state' => 'pass',
                'summary' => 'Valid inbound mail exchangers are published.',
                'service_mode' => 'accepts_mail',
                'targets' => [[
                    'preference' => 10,
                    'normalized_hostname' => 'mail.example.test',
                    'hostname' => 'mail.example.test',
                    'status' => 'usable',
                ]],
            ],
        ], $overrides);
    }

    protected function renderDnsSection(array $records, ?array $dmarcStatus = null, array $statusCards = [], ?array $mxInfo = null): string
    {
        if ($statusCards === []) {
            $mapper = new ScanReportStatusMapper();
            $statusCards = $mapper->buildStatusCards(
                ['spf' => ['lookups' => 1, 'valid' => true], 'blacklist' => ['total_checks' => 1, 'listed_count' => 0]],
                $records,
                50
            );
        }

        return view('scans.partials._dns-section', [
            'records' => $records,
            'spfLookupCount' => 1,
            'spfMax' => 10,
            'domain' => $this->sampleDomain(),
            'dmarcStatus' => $dmarcStatus,
            'statusCards' => $statusCards,
            'dmarcPolicy' => 'reject',
            'dmarcAligned' => true,
            'mxInfo' => $mxInfo ?? $this->sampleMxInfo(),
        ])->render();
    }

    public function test_summary_tiles_render_for_core_records(): void
    {
        $html = $this->renderDnsSection($this->baseRecords(), [
            'rua_link_state' => DmarcStatusService::RUA_LINK_NOT_CONNECTED,
            'has_rua' => true,
            'has_dmarc_record' => true,
            'status' => DmarcStatusService::STATUS_ENABLED_NOT_MXSCAN,
        ]);

        foreach (['SPF', 'DKIM DNS', 'DMARC', 'DMARC Reports', 'MX', 'TLS-RPT', 'MTA-STS'] as $label) {
            $this->assertStringContainsString($label, $html);
        }
    }

    public function test_spf_missing_state_is_visible_and_actionable(): void
    {
        $html = $this->renderDnsSection($this->baseRecords());

        $this->assertStringContainsString('Missing', $html);
        $this->assertStringContainsString('No SPF record found', $html);
        $this->assertStringContainsString('Add SPF', $html);
    }

    public function test_dkim_shows_selector_count_and_dns_only_note(): void
    {
        $html = $this->renderDnsSection($this->baseRecords());

        $this->assertStringContainsString('valid DKIM key', $html);
        $this->assertStringContainsString('published DNS keys only', $html);
    }

    public function test_dmarc_reports_relink_copy_shown_once(): void
    {
        $html = $this->renderDnsSection($this->baseRecords(), [
            'status' => DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING,
            'label' => 'Enabled (MXScan) — Waiting',
            'badge_color' => 'blue',
            'helper_text' => 'Good — reports usually arrive within 24–48 hours.',
            'has_dmarc_record' => true,
            'has_rua' => true,
            'has_mxscan_rua' => false,
            'has_reports' => false,
            'rua_link_state' => DmarcStatusService::RUA_LINK_DETECTED_UNLINKED,
            'rua_link_label' => 'MXScan reporting is present, but it is not linked to this domain.',
            'rua_link_cta' => 'Relink MXScan reporting',
        ]);

        $this->assertStringContainsString('Relink required', $html);
        $this->assertStringContainsString('Fix reporting', $html);
        $this->assertStringContainsString('not linked to this domain', $html);
        $this->assertEquals(1, substr_count($html, 'MXScan reporting is present, but not linked to this domain.'));
        $this->assertStringNotContainsString('Relink MXScan reporting', $html);
    }

    public function test_detail_groups_render_in_expected_order(): void
    {
        $html = $this->renderDnsSection($this->baseRecords());

        $authPos = strpos($html, 'Authentication');
        $routingPos = strpos($html, 'Mail routing &amp; reporting');
        $transportPos = strpos($html, 'Transport security');
        $spfDetailPos = strpos($html, 'id="dns-spf-detail"');
        $mxDetailPos = strpos($html, 'id="dns-mx-detail"');
        $mtaDetailPos = strpos($html, 'id="dns-mtasts-detail"');

        $this->assertNotFalse($authPos);
        $this->assertNotFalse($routingPos);
        $this->assertNotFalse($transportPos);
        $this->assertLessThan($routingPos, $authPos);
        $this->assertLessThan($transportPos, $routingPos);
        $this->assertLessThan($mxDetailPos, $spfDetailPos);
        $this->assertLessThan($mtaDetailPos, $mxDetailPos);
    }

    public function test_long_record_values_use_code_value_container(): void
    {
        $longSpf = 'v=spf1 ' . str_repeat('include:example.test ', 40) . '-all';
        $records = $this->baseRecords([
            'SPF' => ['status' => 'found', 'data' => $longSpf],
        ]);

        $html = $this->renderDnsSection($records);

        $this->assertStringContainsString('Show full value', $html);
        $this->assertStringContainsString('overflow-x-auto', $html);
        $this->assertStringContainsString('break-all', $html);
    }

    public function test_copy_actions_render_with_accessible_labels(): void
    {
        $html = $this->renderDnsSection($this->baseRecords([
            'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
            'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
        ]));

        $this->assertStringContainsString('aria-label="Copy SPF record"', $html);
        $this->assertStringContainsString('aria-label="Copy DMARC record"', $html);
    }

    public function test_configured_records_avoid_loud_green_panels(): void
    {
        $records = $this->baseRecords([
            'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
            'TLS-RPT' => ['status' => 'found', 'data' => 'v=TLSRPTv1; rua=mailto:tls@example.test'],
            'MTA-STS' => ['status' => 'found', 'data' => 'v=STSv1; id=20240101'],
        ]);

        $html = $this->renderDnsSection($records);

        $this->assertStringNotContainsString('bg-green-50', $html);
        $this->assertStringContainsString('Configured', $html);
    }

    public function test_presenter_summary_tile_count(): void
    {
        $records = $this->baseRecords();
        $mapper = new ScanReportStatusMapper();
        $statusCards = $mapper->buildStatusCards([], $records, 50);

        $presenter = new DnsSectionPresenter(
            records: $records,
            statusCards: $statusCards,
            dmarcStatus: ['status' => 'not_enabled', 'label' => 'Not Enabled'],
            spfLookupCount: 1,
            domain: $this->sampleDomain(),
        );

        $this->assertCount(8, $presenter->summaryTiles());
    }
}
