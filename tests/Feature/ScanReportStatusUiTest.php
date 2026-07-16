<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Services\ScanReport\ScanRecommendationService;
use App\Services\ScanReport\ScanReportStatusMapper;
use Tests\TestCase;

class ScanReportStatusUiTest extends TestCase
{
    protected function sampleDomain(): Domain
    {
        $domain = new Domain([
            'domain' => 'example.test',
            'domain_expiry_source' => null,
            'ssl_expiry_source' => null,
            'domain_expires_at' => now()->addDays(100),
            'ssl_expires_at' => now()->addDays(100),
        ]);
        $domain->id = 1;
        $domain->domain_expiry_detected_at = null;
        $domain->ssl_expiry_detected_at = null;

        return $domain;
    }

    public function test_kpi_acceptance_a_missing_spf_never_shows_ok_zero_of_ten(): void
    {
        $mapper = new ScanReportStatusMapper();
        $statusCards = $mapper->buildStatusCards(
            [
                'spf' => ['lookups' => 0, 'valid' => true],
                'blacklist' => ['total_checks' => 5, 'listed_count' => 0],
            ],
            [
                'SPF' => ['status' => 'missing'],
                'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
                'BIMI' => ['status' => 'missing'],
            ],
            40
        );

        $html = view('scans.partials._kpi-cards', [
            'enabled' => ['dns' => true, 'spf' => true, 'blacklist' => true],
            'score' => 40,
            'scoreDelta' => null,
            'statusCards' => $statusCards,
            'blacklistHits' => 0,
            'blacklistTotal' => 5,
            'spfLookupCount' => null,
            'spfMax' => 10,
            'dmarcPolicy' => 'reject',
            'dmarcAligned' => true,
            'tlsrptOk' => false,
            'mtastsOk' => false,
            'domainDays' => 100,
            'sslDays' => 100,
            'bimiOk' => false,
            'scoreBreakdown' => [],
            'scoreDeductions' => [],
            'domain' => $this->sampleDomain(),
        ])->render();

        $this->assertStringContainsString('Email Security Score', $html);
        $this->assertStringNotContainsString('Deliverability Score', $html);
        $this->assertStringContainsString('Missing', $html);
        $this->assertStringContainsString('Lookup count not applicable', $html);
        $this->assertStringNotContainsString('0 of 10', $html);
        $this->assertStringContainsString('Fix SPF', $html);
    }

    public function test_kpi_acceptance_b_zero_blacklist_checks_not_green_clean(): void
    {
        $mapper = new ScanReportStatusMapper();
        $statusCards = $mapper->buildStatusCards(
            ['blacklist' => ['total_checks' => 0, 'listed_count' => 0, 'is_clean' => true]],
            ['SPF' => ['status' => 'found', 'data' => 'v=spf1 -all']],
            50
        );

        $html = view('scans.partials._kpi-cards', [
            'enabled' => ['dns' => true, 'spf' => true, 'blacklist' => true],
            'score' => 50,
            'statusCards' => $statusCards,
            'blacklistHits' => 0,
            'blacklistTotal' => 0,
            'spfLookupCount' => 2,
            'spfMax' => 10,
            'dmarcPolicy' => null,
            'dmarcAligned' => false,
            'tlsrptOk' => false,
            'mtastsOk' => false,
            'domainDays' => 100,
            'sslDays' => 100,
            'bimiOk' => false,
            'scoreBreakdown' => [],
            'scoreDeductions' => [],
            'domain' => $this->sampleDomain(),
        ])->render();

        $this->assertStringContainsString('Not scanned', $html);
        $this->assertStringNotContainsString('text-green-700 dark:text-green-300">
          Clean', $html);
        $this->assertDoesNotMatchRegularExpression('/text-green-[^"]*">\s*Clean\s*</', $html);
    }

    public function test_dns_section_acceptance_c_dkim_dns_only_wording(): void
    {
        $mapper = new ScanReportStatusMapper();
        $dkim = $mapper->mapDkim([
            'status' => 'found',
            'data' => [
                ['selector' => 'google', 'record' => 'v=DKIM1; p=abc'],
            ],
        ]);

        $html = view('scans.partials._dns-section', [
            'records' => [
                'MX' => ['status' => 'found', 'data' => []],
                'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                'DKIM' => [
                    'status' => 'found',
                    'data' => [['selector' => 'google', 'record' => 'v=DKIM1; p=abc']],
                ],
                'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
                'TLS-RPT' => ['status' => 'missing'],
                'MTA-STS' => ['status' => 'missing'],
                'BIMI' => ['status' => 'missing'],
            ],
            'spfLookupCount' => 1,
            'spfMax' => 10,
            'domain' => $this->sampleDomain(),
            'dmarcStatus' => null,
            'statusCards' => ['dkim' => $dkim],
            'dmarcPolicy' => 'reject',
            'dmarcAligned' => true,
        ])->render();

        $this->assertStringContainsString('valid DKIM key', $html);
        $this->assertStringContainsString('DNS publication confirmed', $html);
        $this->assertStringContainsString('DMARC-report evidence', $html);
        $this->assertStringNotContainsString('signing verified', strtolower($html));
    }

    public function test_fix_pack_acceptance_d_spf_before_mtasts_and_add_spf_copy(): void
    {
        $domain = $this->sampleDomain();
        $service = new ScanRecommendationService(
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
        $result = [
            'dns' => [
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'missing'],
                    'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                    'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
                    'TLS-RPT' => ['status' => 'missing'],
                    'MTA-STS' => ['status' => 'missing'],
                    'BIMI' => ['status' => 'missing'],
                ],
            ],
            'blacklist' => ['total_checks' => 3, 'listed_count' => 0],
        ];
        $recs = $service->build($domain, $result);
        $allClear = $service->evaluateAllClear($result);

        $html = view('scans.partials._fix-pack', [
            'recommendations' => $recs,
            'allClear' => $allClear,
            'domain' => $domain,
            'domainDays' => 90,
            'sslDays' => 90,
        ])->render();

        $this->assertStringContainsString('Add SPF Record', $html);
        $spfPos = strpos($html, 'Add SPF Record');
        $mtaPos = strpos($html, 'Add MTA-STS Policy');
        $this->assertNotFalse($spfPos);
        $this->assertNotFalse($mtaPos);
        $this->assertLessThan($mtaPos, $spfPos);
    }
}
