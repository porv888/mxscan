<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Support\EmailSecurity\ResetsScanPipelineContainer;
use Tests\TestCase;

class MxscanMeRenderedDashboardTest extends TestCase
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

    public function test_mxscan_me_rendered_dashboard_has_no_contradictory_copy(): void
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
        $viewData['isBlacklistOnly'] = false;
        $viewData['isFirstFinishedScan'] = true;
        $viewData['snapshot'] = null;
        $viewData['lastSnapshot'] = null;
        $viewData['spfSuggestion'] = null;
        $viewData['tlsrptOk'] = ($viewData['statusCards']['tlsrpt']['state'] ?? '') === ScanReportStatusMapper::PASS;
        $viewData['mtastsOk'] = false;
        $viewData['bimiHasData'] = false;
        $viewData['bimiOk'] = false;
        $viewData['domainDays'] = 120;
        $viewData['sslDays'] = null;
        $viewData['scoreDeductions'] = [];

        $html = view('scans.show', $viewData)->render();
        $lower = strtolower($html);

        $this->assertStringContainsString('64', $html);
        $this->assertStringContainsString('3 valid dkim selectors are published', $lower);
        $this->assertStringContainsString('default', $lower);
        $this->assertStringContainsString('quarantine', $lower);
        $this->assertStringContainsString('alignment not verified', $lower);

        $this->assertStringNotContainsString('no dkim selectors discovered', $lower);
        $this->assertStringNotContainsString('policy is monitoring only', $lower);
        $this->assertStringNotContainsString('mxscan.me does not match mxscan.me', $lower);
        $this->assertStringNotContainsString('mta-sts.mxscan.me does not match mta-sts.mxscan.me', $lower);
        $this->assertStringNotContainsString('mail.mxscan.me does not match mail.mxscan.me', $lower);

        $this->assertDoesNotMatchRegularExpression('/dkim[^<]{0,120}>\s*missing\s*</i', $html);

        $this->assertStringContainsString('mx-tech-category-card', $html);
        $this->assertStringContainsString('mx-evidence-panel', $html);
        $this->assertStringContainsString('mx-tech-issue-panel', $html);
        $this->assertStringContainsString('mx-tech-solution-panel', $html);
        $this->assertStringContainsString('mx-tech-check-row--failing', $html);
        $this->assertStringContainsString('mx-tech-check-row--passing', $html);
        $this->assertStringContainsString('mx-status-pill', $html);
        $this->assertStringContainsString('data-tech-category', $html);
        $this->assertStringContainsString('data-recommendation-card', $html);
        $this->assertStringContainsString('mx-dkim-table', $html);
        $this->assertStringNotContainsString('Hide resolved checks', $html);

        $this->assertDoesNotMatchRegularExpression('/<details[^>]*id="tech-dkim"[^>]*\sopen/si', $html);
        $this->assertMatchesRegularExpression('/<details[^>]*id="tech-spf"[^>]*\sopen/si', $html);

        $this->assertStringContainsString('SPF is missing', $html);
        $this->assertLessThan(
            strpos($html, 'DMARC reject policy'),
            strpos($html, 'SPF is missing'),
        );
        $this->assertStringContainsString('Fix SPF', $html);
        $this->assertStringContainsString('Checks passing', $html);
        $this->assertStringContainsString('Checks needing action', $html);
        $this->assertStringNotContainsString('Score change: +0', $html);
        $this->assertStringContainsString('Published', $html);
        $this->assertDoesNotMatchRegularExpression('/DKIM.{0,200}Configured/is', $html);

        $dmarcPolicyStart = strpos($html, 'id="tech-dmarc"');
        $dmarcReportsStart = strpos($html, 'id="tech-dmarc_reports"');
        $this->assertNotFalse($dmarcPolicyStart);
        $this->assertNotFalse($dmarcReportsStart);
        $dmarcPolicy = substr($html, $dmarcPolicyStart, $dmarcReportsStart - $dmarcPolicyStart);
        $this->assertStringContainsString('24/24 points', $dmarcPolicy);
        $this->assertStringNotContainsString('−6 pts', $dmarcPolicy);

        $dmarcReports = substr($html, $dmarcReportsStart, 30000);
        $this->assertStringContainsString('0/6 points', $dmarcReports);
        $this->assertStringContainsString('−6 pts', $dmarcReports);
        $this->assertStringContainsString('Old MXScan address detected', $dmarcReports);
        $this->assertStringContainsString('mxscan.me._report._dmarc.dmarc.brevo.com', $dmarcReports);
        $this->assertStringContainsString('The owner of', $dmarcReports);
        $this->assertStringContainsString('Copy host', $dmarcReports);
        $this->assertStringContainsString('Copy value', $dmarcReports);
        $this->assertStringContainsString('Copy full record', $dmarcReports);
        $this->assertStringContainsString('data-copy-text', $html);
        $this->assertStringContainsString('data-copy-feedback', $html);
        $this->assertStringNotContainsString('<span class="sr-only">Copy host</span>', $html);
        $this->assertDoesNotMatchRegularExpression('/<option value="godaddy"[^>]*selected/i', $html);
        $this->assertStringContainsString('Select DNS provider', $html);
    }
}
