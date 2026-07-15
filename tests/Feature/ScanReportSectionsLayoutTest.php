<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\ScanReport\ScanRecommendationService;
use App\Services\ScanReport\ScanReportStatusMapper;
use App\View\Presenters\ReportTechnicalChecksPresenter;
use App\View\Presenters\ScanReportPresenter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\Support\EmailSecurity\ResetsScanPipelineContainer;
use Tests\TestCase;

class ScanReportSectionsLayoutTest extends TestCase
{
    use RefreshDatabase;
    use ResetsScanPipelineContainer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->resetScanPipelineContainer();
    }

    protected function renderReportHtml(): string
    {
        $domain = Domain::factory()->create(['domain' => 'mxscan.me']);
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
            'dmarc' => [
                'analysis' => DmarcFixtureBuilder::nativeAnalysis([
                    'policy' => [
                        'published_p' => 'reject',
                        'effective_policy' => 'reject',
                        'pct' => 100,
                        'testing_mode' => false,
                        'enforcement' => 'reject',
                    ],
                    'alignment' => ['dkim' => 'strict', 'spf' => 'strict'],
                    'aggregate_reporting' => [
                        'configured' => true,
                        'destinations' => [[
                            'normalized_destination' => 'dmarc@mxscan.me',
                            'destination_domain' => 'mxscan.me',
                            'internal' => true,
                        ]],
                        'mxscan_expectation' => [
                            'expected_address' => 'dmarc+token@mxscan.me',
                            'present' => true,
                            'other_valid_destination_exists' => false,
                        ],
                    ],
                ], 'v=DMARC1; p=reject; rua=mailto:dmarc@mxscan.me'),
            ],
            'certificates' => [
                'analysis' => [
                    'state' => 'warning',
                    'endpoints' => [[
                        'endpoint_type' => 'primary_https',
                        'hostname' => 'mxscan.me',
                        'certificate_status' => 'hostname_mismatch',
                        'verification_state' => 'hostname_mismatch',
                        'protocol_status' => 'evaluated',
                        'matched_identity' => 'www.example.com',
                        'san_dns' => ['www.example.com'],
                    ]],
                ],
            ],
        ];
        $mapper = new ScanReportStatusMapper();
        $statusCards = $mapper->buildStatusCards($resultJson, $records, 70);
        $recommendations = (new ScanRecommendationService(
            $mapper,
            new \App\Domain\EmailSecurity\Checks\SPF\Recommendations\SpfRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\DMARC\Recommendations\DmarcRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\DKIM\Recommendations\DkimRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\MtaSts\Recommendations\MtaStsRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Mx\Recommendations\MxRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\TlsRpt\Recommendations\TlsRptRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Certificates\Recommendations\CertificateRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Bimi\BimiRecommendationEvaluator(),
            new \App\Domain\EmailSecurity\Checks\Blacklist\Recommendations\BlacklistRecommendationEvaluator(),
        ))->build($domain, $resultJson, $records);

        $user = User::factory()->create();
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'status' => 'finished',
            'score' => 70,
            'result_json' => $resultJson,
        ]);

        $this->actingAs($user);

        return view('scans.show', [
            'scan' => $scan,
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
            'dmarcAlignmentVerification' => \App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification::NOT_VERIFIED,
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
            'resultData' => $resultJson,
        ])->render();
    }

    public function test_technical_checks_use_category_cards_and_status_pills(): void
    {
        $html = $this->renderReportHtml();

        $this->assertStringContainsString('data-tech-category', $html);
        $this->assertStringContainsString('mx-tech-category-card', $html);
        $this->assertStringContainsString('mx-status-pill', $html);
        $this->assertStringContainsString('mx-evidence-panel', $html);
        $this->assertStringContainsString('Expand all', $html);
        $this->assertStringContainsString('Collapse all', $html);
        $this->assertStringContainsString('Authentication', $html);
        $this->assertStringContainsString('data-tech-check', $html);
    }

    public function test_what_to_fix_uses_recommendation_cards_with_endpoint_metadata(): void
    {
        $html = $this->renderReportHtml();

        $this->assertStringContainsString('data-recommendation-card', $html);
        $this->assertStringContainsString('data-recommendation-item', $html);
        $this->assertStringContainsString('mx-recommendation-card', $html);
        $this->assertStringContainsString('Resolve the highest-impact issues first.', $html);
        $this->assertStringContainsString('Why this matters', $html);
        $this->assertStringContainsString('min-h-[44px]', $html);
    }

    public function test_presenter_endpoint_metadata_extracts_certificate_host(): void
    {
        $presenter = new ScanReportPresenter(
            domain: new Domain(['domain' => 'mxscan.me']),
            score: 70,
            scoreDelta: null,
            statusCards: [],
            recommendations: [[
                'key' => 'certificates',
                'severity' => 'high',
                'title' => 'Fix certificate hostname mismatch',
                'explanation' => 'The certificate for mxscan.me presents identity "www.example.com" which does not match the requested hostname.',
            ]],
            allClear: ['state' => 'needs_fixes'],
            scoreBreakdown: [],
            scoreTrend: ['labels' => [], 'scores' => []],
        );

        $endpoint = $presenter->endpointMetadataForRecommendation($presenter->coreRecommendations()[0]);

        $this->assertNotNull($endpoint);
        $this->assertSame('Primary HTTPS', $endpoint['category']);
        $this->assertSame('mxscan.me', $endpoint['endpoint']);
    }

    public function test_technical_checks_presenter_builds_category_summary(): void
    {
        $domain = new Domain(['domain' => 'mxscan.me']);
        $domain->id = 1;

        $dnsPresenter = new \App\View\Presenters\DnsSectionPresenter(
            records: [
                'SPF' => ['status' => 'missing'],
                'DKIM' => ['status' => 'found', 'data' => [['selector' => 'default', 'record' => 'v=DKIM1; p=abc']]],
                'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=quarantine'],
            ],
            statusCards: (new ScanReportStatusMapper())->buildStatusCards([], [
                'SPF' => ['status' => 'missing'],
                'DKIM' => ['status' => 'found', 'data' => [['selector' => 'default', 'record' => 'v=DKIM1; p=abc']]],
                'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=quarantine'],
            ], 50),
            dmarcStatus: null,
            spfLookupCount: null,
            domain: $domain,
            dmarcPolicy: 'quarantine',
            dmarcAligned: false,
            dmarcAlignmentVerification: \App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification::NOT_VERIFIED,
            spfMax: 10,
            mxInfo: null,
            bimiInfo: null,
            dkimInfo: null,
            scan: null,
        );

        $groups = (new ReportTechnicalChecksPresenter(
            dns: $dnsPresenter,
            domain: $domain,
            blacklistEnabled: false,
        ))->groups();

        $auth = collect($groups)->firstWhere('label', 'Authentication');
        $this->assertNotNull($auth);
        $this->assertArrayHasKey('summary', $auth);
        $this->assertStringContainsString('configured', strtolower($auth['summary']['summary']));
    }
}
