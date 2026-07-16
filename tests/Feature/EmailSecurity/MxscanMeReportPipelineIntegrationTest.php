<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\ScanReport\ScanRecommendationService;
use App\View\Presenters\ScanReportPresenter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Support\EmailSecurity\ResetsScanPipelineContainer;
use Tests\TestCase;

class MxscanMeReportPipelineIntegrationTest extends TestCase
{
    use CreatesPlanUsers;
    use RefreshDatabase;
    use ResetsScanPipelineContainer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->resetScanPipelineContainer();
        $this->setUpPlanTables();
    }

    public function test_mxscan_me_fixture_report_pipeline_is_internally_consistent(): void
    {
        $user = $this->createPremiumUser();
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

        $this->actingAs($user);

        $viewData = app(ScanReportFactoryInterface::class)->build($scan, $domain)->toArray();
        $records = $viewData['records'];
        $statusCards = $viewData['statusCards'];
        $breakdown = $viewData['scoreBreakdown'];

        $this->assertSame(64, $viewData['score']);
        $this->assertSame(64, (int) collect($breakdown)->sum('earned'));

        $dkim = $statusCards['dkim'];
        $this->assertSame(ScanReportStatusMapper::PASS, $dkim['state']);
        $this->assertSame(20, (int) collect($breakdown)->firstWhere('key', 'dkim')['earned']);
        $this->assertGreaterThanOrEqual(1, $dkim['count']);
        $this->assertStringContainsString('valid dkim key', strtolower((string) $dkim['status']));
        $this->assertStringContainsString('default', json_encode($resultJson['dkim']['analysis']['selectors'] ?? []));

        $dmarc = $statusCards['dmarc'];
        $this->assertSame('quarantine', $dmarc['policy']);
        $this->assertSame(ScanReportStatusMapper::PASS, $dmarc['state']);
        $this->assertNull($viewData['dmarcAligned']);
        $dmarcScore = collect($breakdown)->firstWhere('key', 'dmarc');
        $this->assertSame(24, $dmarcScore['earned']);
        $this->assertSame(24, $dmarcScore['subcomponents'][0]['earned']);
        $this->assertSame(24, $dmarcScore['subcomponents'][0]['possible']);
        $this->assertSame(0, $dmarcScore['subcomponents'][1]['earned']);
        $this->assertSame(6, $dmarcScore['subcomponents'][1]['possible']);

        $dmarcRemediation = $viewData['technicalRemediation']['dmarc'];
        $canonical = $dmarcRemediation['mxscan_address'];
        $this->assertSame('Old MXScan address detected', $dmarcRemediation['mxscan_link_state']);
        $this->assertSame(1, substr_count(strtolower($dmarcRemediation['corrected_value']), strtolower($canonical)));
        $this->assertStringContainsString('mailto:rua@dmarc.brevo.com', $dmarcRemediation['corrected_value']);
        $this->assertNotEmpty($dmarcRemediation['diff']['remove']);
        $this->assertSame([$canonical], $dmarcRemediation['diff']['add']);
        $this->assertSame('dmarc.brevo.com', $dmarcRemediation['external_destinations'][0]['owner']);
        $this->assertSame(
            'mxscan.me._report._dmarc.dmarc.brevo.com',
            $dmarcRemediation['external_destinations'][0]['authorization_host'],
        );
        $this->assertFalse($dmarcRemediation['external_destinations'][0]['customer_controls_zone']);

        $presenter = new ScanReportPresenter(
            domain: $domain,
            score: 64,
            scoreDelta: null,
            statusCards: $statusCards,
            recommendations: $viewData['recommendations'],
            allClear: $viewData['allClear'],
            scoreBreakdown: $breakdown,
            scoreTrend: $viewData['scoreTrend'],
            blacklistHits: $viewData['blacklistHits'],
            blacklistTotal: $viewData['blacklistTotal'],
            dmarcPolicy: $viewData['dmarcPolicy'],
        );

        $auth = collect($presenter->authStripItems())->keyBy('key');
        $this->assertSame('Published', $auth['dkim']['status']);
        $this->assertStringContainsString('selector', $auth['dkim']['explanation']);
        $this->assertStringNotContainsString('No DKIM selectors discovered', $auth['dkim']['explanation']);
        $this->assertStringNotContainsString('monitoring only', strtolower($auth['dmarc']['explanation']));

        $recService = app(ScanRecommendationService::class);
        $recommendations = $recService->build($domain, $resultJson, $records);
        foreach ($recommendations as $rec) {
            $text = strtolower(($rec['title'] ?? '') . ' ' . ($rec['explanation'] ?? ''));
            $this->assertStringNotContainsString('mxscan.me does not match mxscan.me', $text);
            $this->assertStringNotContainsString('mta-sts.mxscan.me does not match mta-sts.mxscan.me', $text);
            $this->assertStringNotContainsString('mail.mxscan.me does not match mail.mxscan.me', $text);
        }
    }
}
