<?php

namespace Tests\Unit;

use App\Models\Domain;
use App\Services\ScanReport\ScanRecommendationService;
use App\Services\ScanReport\ScanReportStatusMapper;
use Tests\TestCase;

class ScanRecommendationServiceTest extends TestCase
{
    private function makeService(): ScanRecommendationService
    {
        return new ScanRecommendationService(
            new ScanReportStatusMapper(),
            new \App\Domain\EmailSecurity\Checks\SPF\Recommendations\SpfRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\DMARC\Recommendations\DmarcRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\DKIM\Recommendations\DkimRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\MtaSts\Recommendations\MtaStsRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Mx\Recommendations\MxRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\TlsRpt\Recommendations\TlsRptRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Certificates\Recommendations\CertificateRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Bimi\BimiRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Blacklist\Recommendations\BlacklistRecommendationEvaluator(),
        );
    }

    public function test_missing_spf_appears_before_tlsrpt_and_mtasts(): void
    {
        $domain = new Domain(['domain' => 'example.test']);
        $service = $this->makeService();

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
        $service = $this->makeService();

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
        $service = $this->makeService();
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

        $this->assertTrue(collect($recs)->contains(fn ($r) => ($r['semantic_key'] ?? $r['key']) === 'verify_dkim_signing_with_sample_message'));
        $verify = collect($recs)->first(fn ($r) => ($r['semantic_key'] ?? $r['key']) === 'verify_dkim_signing_with_sample_message');
        $this->assertStringContainsString('signed message', strtolower($verify['explanation']));
        $this->assertStringNotContainsString('signing verified', strtolower($verify['explanation']));
    }

    public function test_quarantine_dmarc_emits_strengthen_recommendation(): void
    {
        $domain = new Domain(['domain' => 'example.test']);
        $service = $this->makeService();
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
            'dmarc' => [
                'analysis' => [
                    'version' => 'dmarc-native-v1',
                    'protocol_status' => 'valid',
                    'state' => 'pass',
                    'policy' => ['effective_policy' => 'quarantine', 'enforcement' => 'quarantine', 'pct' => 100],
                    'aggregate_reporting' => ['configured' => true, 'destinations' => []],
                ],
            ],
            'spf' => ['lookups' => 1, 'valid' => true],
            'blacklist' => ['total_checks' => 3, 'listed_count' => 0],
        ]);

        $strengthen = collect($recs)->firstWhere('semantic_key', 'strengthen_dmarc_policy');
        $this->assertNotNull($strengthen);
        $this->assertFalse(collect($recs)->contains(fn ($r) => ($r['semantic_key'] ?? '') === 'dmarc_alignment'));
    }

    public function test_reject_dmarc_does_not_emit_alignment_recommendation(): void
    {
        $domain = new Domain(['domain' => 'example.test']);
        $service = $this->makeService();
        $recs = $service->build($domain, [
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                    'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject; adkim=s; aspf=s'],
                    'TLS-RPT' => ['status' => 'found'],
                    'MTA-STS' => ['status' => 'found', 'policy' => 'x'],
                ],
            ],
            'dmarc' => [
                'analysis' => [
                    'version' => 'dmarc-native-v1',
                    'protocol_status' => 'valid',
                    'state' => 'pass',
                    'policy' => ['effective_policy' => 'reject', 'enforcement' => 'reject', 'pct' => 100],
                    'aggregate_reporting' => ['configured' => false, 'destinations' => []],
                    'alignment' => ['dkim' => 'strict', 'spf' => 'strict'],
                ],
            ],
            'spf' => ['lookups' => 1, 'valid' => true],
            'blacklist' => ['total_checks' => 3, 'listed_count' => 0],
        ]);

        $this->assertFalse(collect($recs)->contains(fn ($r) => ($r['semantic_key'] ?? '') === 'dmarc_alignment'));
    }

    public function test_run_scan_shaped_payload_uses_same_service_keys(): void
    {
        $domain = new Domain(['domain' => 'legacy.test']);
        $service = $this->makeService();
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
        $this->assertContains('verify_dkim_signing_with_sample_message', array_column($recs, 'semantic_key'));
    }
}
