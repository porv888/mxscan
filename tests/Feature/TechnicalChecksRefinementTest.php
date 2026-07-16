<?php

namespace Tests\Feature;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Support\EmailSecurity\ResetsScanPipelineContainer;
use Tests\TestCase;

class TechnicalChecksRefinementTest extends TestCase
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

    protected function renderMxscanReportHtml(): string
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
        $viewData['dmarcStatus'] = null;
        $viewData['scoreDeductions'] = [];

        return view('scans.show', $viewData)->render();
    }

    protected function extractCheckSection(string $html, string $checkId): string
    {
        if (!preg_match('/<details[^>]*id="' . preg_quote($checkId, '/') . '"[^>]*>.*?<\/details>/si', $html, $matches)) {
            return '';
        }

        return $matches[0];
    }

    public function test_dkim_renders_compact_selector_summary_and_table(): void
    {
        $html = $this->renderMxscanReportHtml();

        $this->assertStringContainsString('3 valid DKIM selectors are published.', $html);
        $this->assertStringContainsString('mx-dkim-table', $html);
        $this->assertStringContainsString('default._domainkey.mxscan.me', $html);
        $this->assertStringContainsString('s1._domainkey.mxscan.me', $html);
        $this->assertStringContainsString('s2._domainkey.mxscan.me', $html);

        $dkimSection = $this->extractCheckSection($html, 'tech-dkim');
        $this->assertNotSame('', $dkimSection);
        $this->assertStringNotContainsString('Configured', $dkimSection);
        $this->assertStringNotContainsString('mx-dns-value-block', $dkimSection);
    }

    public function test_accordion_defaults_expand_missing_spf_and_collapse_passing_dkim(): void
    {
        $html = $this->renderMxscanReportHtml();

        $this->assertMatchesRegularExpression('/<details[^>]*id="tech-spf"[^>]*\sopen/si', $html);
        $this->assertDoesNotMatchRegularExpression('/<details[^>]*id="tech-dkim"[^>]*\sopen/si', $html);
    }

    public function test_toolbar_uses_hide_passing_checks_label(): void
    {
        $html = $this->renderMxscanReportHtml();

        $this->assertStringContainsString('Hide passing checks', $html);
        $this->assertStringNotContainsString('Hide resolved checks', $html);
        $this->assertStringContainsString('mx-tech-toolbar', $html);
    }

    public function test_category_header_uses_passing_terminology_and_issue_count(): void
    {
        $html = $this->renderMxscanReportHtml();

        $this->assertStringContainsString('passing', strtolower($html));
        $this->assertStringContainsString('need attention', strtolower($html));
        $this->assertStringNotContainsString('Issues found', $html);
        $this->assertMatchesRegularExpression('/>\s*\d+\s+issues?\s*</i', $html);
    }

    public function test_spf_panel_is_compact_without_duplicate_action_or_generated_record(): void
    {
        $html = $this->renderMxscanReportHtml();
        $spfSection = $this->extractCheckSection($html, 'tech-spf');

        $this->assertStringContainsString('Why this matters', $spfSection);
        $this->assertStringContainsString('SPF identifies which services may send email for this domain.', $spfSection);
        $this->assertStringContainsString('View fix instructions', $spfSection);
        $this->assertStringContainsString('#what-to-fix', $spfSection);
        $this->assertStringNotContainsString('v=spf1', strtolower($spfSection));
        $this->assertStringNotContainsString('google.com', strtolower($spfSection));
        $this->assertStringNotContainsString('include:sendgrid', strtolower($spfSection));

        $panel = '';
        if (preg_match('/id="tech-spf-panel"[^>]*>.*?<\/div>\s*<\/details>/si', $spfSection, $panelMatch)) {
            $panel = $panelMatch[0];
        }

        $this->assertStringNotContainsString('Add SPF', $panel);
        $this->assertStringContainsString('View fix instructions', $panel);
    }

    public function test_summaries_do_not_contain_duplicate_periods(): void
    {
        $html = $this->renderMxscanReportHtml();

        preg_match_all('/class="mx-tech-check-desc"[^>]*>(.*?)<\/span>/si', $html, $matches);
        foreach ($matches[1] as $summary) {
            $text = html_entity_decode(strip_tags($summary));
            $this->assertDoesNotMatchRegularExpression('/\.\s*\./', $text, 'Summary contains duplicate period: ' . $text);
        }
    }

    public function test_existing_accuracy_invariants_remain_passing(): void
    {
        $html = $this->renderMxscanReportHtml();
        $lower = strtolower($html);

        $this->assertStringContainsString('quarantine', $lower);
        $this->assertStringContainsString('alignment not verified', $lower);
        $this->assertStringNotContainsString('no dkim selectors discovered', $lower);
        $this->assertStringNotContainsString('policy is monitoring only', $lower);
        $this->assertStringNotContainsString('mxscan.me does not match mxscan.me', $lower);
        $this->assertDoesNotMatchRegularExpression('/dkim[^<]{0,120}>\s*missing\s*</i', $html);
    }
}
