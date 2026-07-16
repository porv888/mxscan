<?php

namespace Tests\Feature;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;
use App\Models\DomainSender;
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

    protected function renderMxscanReportHtml(array $senders = []): string
    {
        $user = $this->createPremiumUser();
        $domain = Domain::factory()->create([
            'user_id' => $user->id,
            'domain' => 'mxscan.me',
        ]);

        foreach ($senders as $sender) {
            $domain->senders()->create($sender + [
                'source' => DomainSender::SOURCE_DETECTED,
                'confidence' => DomainSender::CONFIDENCE_CONFIRMED,
                'confirmation_status' => DomainSender::STATUS_CONFIRMED,
                'confirmed_by' => $user->id,
                'confirmed_at' => now(),
                'last_seen_at' => now(),
                'is_active' => true,
                'fingerprint' => DomainSender::fingerprint(
                    $sender['sender_type'],
                    $sender['provider'] ?? null,
                    $sender['mechanism'],
                    $sender['value'],
                ),
            ]);
        }

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

    public function test_missing_spf_renders_sender_confirmation_and_solution_builder(): void
    {
        $html = $this->renderMxscanReportHtml();
        $spfSection = $this->extractCheckSection($html, 'tech-spf');

        $this->assertStringContainsString('mx-tech-issue-panel', $spfSection);
        $this->assertStringContainsString('mx-tech-evidence-panel', $spfSection);
        $this->assertStringContainsString('mx-tech-solution-panel', $spfSection);
        $this->assertStringContainsString('No TXT record beginning with', $spfSection);
        $this->assertStringContainsString('Detected infrastructure', $spfSection);
        $this->assertStringContainsString('mail.mxscan.me', $spfSection);
        $this->assertStringContainsString('89.149.243.245', $spfSection);
        $this->assertStringContainsString('2001:1af8:5301:131:1c00:62ff:fe00:1efc', $spfSection);
        $this->assertStringContainsString('Does this server also send outgoing email', $spfSection);
        $this->assertStringContainsString('Yes, authorize it', $spfSection);
        $this->assertStringContainsString('Not sure', $spfSection);
        $this->assertStringContainsString('data-sender-confidence="pending"', $spfSection);
        $this->assertStringContainsString('Type', $spfSection);
        $this->assertStringContainsString('Host', $spfSection);
        $this->assertStringContainsString('Value', $spfSection);
        $this->assertStringContainsString('TTL', $spfSection);
        $this->assertStringContainsString('Copy value', $spfSection);
        $this->assertStringContainsString('Up to +20 points', $spfSection);
        $this->assertStringContainsString('Cannot generate yet', $spfSection);
        $this->assertStringNotContainsString('View fix instructions', $spfSection);
        $this->assertSame(1, substr_count($spfSection, 'mx-tech-rescan-button'));
    }

    public function test_confirmed_detected_senders_generate_soft_fail_spf_with_fifteen_points(): void
    {
        $html = $this->renderMxscanReportHtml([
            ['sender_type' => 'own_server', 'provider' => null, 'mechanism' => 'ip4', 'value' => '89.149.243.245'],
            ['sender_type' => 'own_server', 'provider' => null, 'mechanism' => 'ip6', 'value' => '2001:1af8:5301:131:1c00:62ff:fe00:1efc'],
        ]);
        $spfSection = $this->extractCheckSection($html, 'tech-spf');

        $this->assertStringContainsString(
            'v=spf1 ip4:89.149.243.245 ip6:2001:1af8:5301:131:1c00:62ff:fe00:1efc ~all',
            $spfSection,
        );
        $this->assertStringContainsString('15/20', $spfSection);
        $this->assertStringContainsString('Suggested starting SPF record', $spfSection);
        $this->assertStringNotContainsString('~all</code></dd></div></dl></div><strong>20/20', $spfSection);
    }

    public function test_mta_sts_and_dmarc_issues_render_generated_configuration(): void
    {
        $html = $this->renderMxscanReportHtml();
        $mtaSts = $this->extractCheckSection($html, 'tech-mtasts');
        $dmarcReports = $this->extractCheckSection($html, 'tech-dmarc_reports');

        $this->assertStringContainsString('MTA-STS DNS record', $mtaSts);
        $this->assertStringContainsString('v=STSv1; id=', $mtaSts);
        $this->assertStringContainsString('https://mta-sts.mxscan.me/.well-known/mta-sts.txt', $mtaSts);
        $this->assertStringContainsString('mode: testing', $mtaSts);
        $this->assertStringContainsString('mx: mail.mxscan.me', $mtaSts);
        $this->assertStringContainsString('Download policy file', $mtaSts);

        $this->assertNotSame('', $dmarcReports);
        $this->assertStringContainsString('Corrected DMARC record', $dmarcReports);
        $this->assertStringContainsString('mailto:dmarc+', $dmarcReports);
        $this->assertStringContainsString('@mxscan.me', $dmarcReports);
        $this->assertStringContainsString('Re-scan domain', $dmarcReports);
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
