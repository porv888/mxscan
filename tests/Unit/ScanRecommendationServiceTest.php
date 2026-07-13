<?php

namespace Tests\Unit;

use App\Models\Domain;
use App\Services\ScanReport\ScanRecommendationService;
use App\Services\ScanReport\ScanReportStatusMapper;
use Tests\TestCase;

class ScanRecommendationServiceTest extends TestCase
{
    public function test_missing_spf_appears_before_tlsrpt_and_mtasts(): void
    {
        $domain = new Domain(['domain' => 'example.test']);
        $service = new ScanRecommendationService(new ScanReportStatusMapper());

        $recs = $service->build($domain, [
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found', 'data' => []],
                    'SPF' => ['status' => 'missing'],
                    'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=quarantine'],
                    'TLS-RPT' => ['status' => 'missing'],
                    'MTA-STS' => ['status' => 'missing'],
                ],
            ],
            'blacklist' => ['total_checks' => 5, 'listed_count' => 0, 'is_clean' => true],
            'spf' => ['lookups' => 0, 'valid' => true],
        ]);

        $keys = array_column($recs, 'key');
        $spfPos = array_search('spf_missing', $keys, true);
        $tlsPos = array_search('tlsrpt', $keys, true);
        $mtaPos = array_search('mtasts', $keys, true);

        $this->assertNotFalse($spfPos);
        $this->assertLessThan($tlsPos, $spfPos);
        $this->assertLessThan($mtaPos, $spfPos);
    }

    public function test_no_all_clear_when_spf_or_dkim_missing_or_blacklist_unchecked(): void
    {
        $service = new ScanRecommendationService(new ScanReportStatusMapper());

        $clear = $service->evaluateAllClear([
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'missing'],
                    'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
                ],
            ],
            'blacklist' => ['total_checks' => 5, 'listed_count' => 0],
        ]);
        $this->assertSame('needs_fixes', $clear['state']);

        $clear = $service->evaluateAllClear([
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                    'DKIM' => ['status' => 'missing'],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
                ],
            ],
            'spf' => ['lookups' => 2, 'valid' => true],
            'blacklist' => ['total_checks' => 5, 'listed_count' => 0],
        ]);
        $this->assertSame('needs_fixes', $clear['state']);

        $clear = $service->evaluateAllClear([
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                    'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
                ],
            ],
            'spf' => ['lookups' => 2, 'valid' => true],
            'blacklist' => ['total_checks' => 0, 'listed_count' => 0],
        ]);
        $this->assertSame('partial_clear', $clear['state']);
        $this->assertStringContainsString('blacklist status was not checked', $clear['message']);
    }

    public function test_missing_dkim_produces_recommendation(): void
    {
        $domain = new Domain(['domain' => 'example.test']);
        $service = new ScanRecommendationService(new ScanReportStatusMapper());
        $recs = $service->build($domain, [
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                    'DKIM' => ['status' => 'missing'],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
                    'TLS-RPT' => ['status' => 'found'],
                    'MTA-STS' => ['status' => 'found', 'policy' => 'x'],
                ],
            ],
            'spf' => ['lookups' => 1, 'valid' => true],
            'blacklist' => ['total_checks' => 3, 'listed_count' => 0],
        ]);

        $this->assertTrue(collect($recs)->contains(fn ($r) => $r['key'] === 'dkim_dns'));
        $dkim = collect($recs)->firstWhere('key', 'dkim_dns');
        $this->assertStringContainsString('DNS', $dkim['explanation']);
        $this->assertStringNotContainsString('signing verified', strtolower($dkim['explanation']));
    }

    public function test_dmarc_missing_alignment_tags_emits_priority_3_recommendation(): void
    {
        $domain = new Domain(['domain' => 'example.test']);
        $service = new ScanRecommendationService(new ScanReportStatusMapper());
        $recs = $service->build($domain, [
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                    'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=quarantine; rua=mailto:rua@example.test'],
                    'TLS-RPT' => ['status' => 'found'],
                    'MTA-STS' => ['status' => 'found', 'policy' => 'x'],
                ],
            ],
            'spf' => ['lookups' => 1, 'valid' => true],
            'blacklist' => ['total_checks' => 3, 'listed_count' => 0],
        ]);

        $alignment = collect($recs)->firstWhere('key', 'dmarc_alignment');
        $this->assertNotNull($alignment);
        $this->assertSame(3, $alignment['priority']);
        $this->assertStringContainsString('adkim=r', $alignment['value']);
        $this->assertStringContainsString('aspf=r', $alignment['value']);
    }

    public function test_dmarc_with_aspf_or_adkim_does_not_emit_alignment_recommendation(): void
    {
        $domain = new Domain(['domain' => 'example.test']);
        $service = new ScanRecommendationService(new ScanReportStatusMapper());
        $recs = $service->build($domain, [
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                    'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject; adkim=r; aspf=r'],
                    'TLS-RPT' => ['status' => 'found'],
                    'MTA-STS' => ['status' => 'found', 'policy' => 'x'],
                ],
            ],
            'spf' => ['lookups' => 1, 'valid' => true],
            'blacklist' => ['total_checks' => 3, 'listed_count' => 0],
        ]);

        $this->assertFalse(collect($recs)->contains(fn ($r) => $r['key'] === 'dmarc_alignment'));
    }

    public function test_run_scan_shaped_payload_uses_same_service_keys(): void
    {
        $domain = new Domain(['domain' => 'legacy.test']);
        $service = new ScanRecommendationService(new ScanReportStatusMapper());
        $records = [
            'MX' => ['status' => 'missing', 'data' => []],
            'SPF' => ['status' => 'missing', 'data' => null],
            'DKIM' => ['status' => 'missing'],
            'DMARC' => ['status' => 'missing', 'data' => null],
            'TLS-RPT' => ['status' => 'missing', 'data' => null],
            'MTA-STS' => ['status' => 'missing', 'data' => null, 'policy' => null],
        ];
        $recs = $service->build($domain, [
            'dns' => ['records' => $records],
            'blacklist' => ['total_checks' => 0, 'listed_count' => 0, 'is_clean' => false],
        ], $records);

        $keys = array_column($recs, 'key');
        $this->assertContains('dmarc_missing', $keys);
        $this->assertContains('spf_missing', $keys);
        $this->assertContains('dkim_dns', $keys);
    }
}
