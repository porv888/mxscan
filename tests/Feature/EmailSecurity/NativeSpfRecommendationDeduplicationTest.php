<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Contracts\RecommendationEngineInterface;
use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Recommendations\ScanRecommendationService;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class NativeSpfRecommendationDeduplicationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['email-security.spf_engine' => 'native']);
    }

    public function test_salesforce_partial_analysis_yields_unique_semantic_keys_in_engine_and_report(): void
    {
        $spfInfo = FixtureLoader::input('spf-salesforce-partial');
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $dnsPayload['records']['SPF'] = ['status' => 'found', 'data' => $spfInfo['record']];
        $resultJson = [
            'dns' => [
                'score' => 73,
                'score_breakdown' => [
                    ['key' => 'spf', 'label' => 'SPF', 'earned' => 8, 'possible' => 20, 'status' => 'partial'],
                ],
                'records' => $dnsPayload['records'],
            ],
            'spf' => $spfInfo,
            'blacklist' => FixtureLoader::input('blacklist-clean'),
        ];

        $domain = Domain::factory()->create(['domain' => 'salesforce.com']);
        $engineItems = app(RecommendationEngineInterface::class)
            ->build($domain, new \App\Domain\EmailSecurity\DTO\ScanResultDTO($resultJson))
            ->items;
        $serviceItems = (new ScanRecommendationService(
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
        ))
            ->build($domain, $resultJson, $dnsPayload['records']);

        foreach ([$engineItems, $serviceItems] as $collection) {
            $semanticKeys = array_column($collection, 'semantic_key');
            $this->assertSameSize($semanticKeys, array_unique($semanticKeys), 'duplicate semantic keys detected');
            $this->assertContains('review_unsupported_spf_macro', $semanticKeys);
            $this->assertNotContains('review_weak_terminal_policy', $semanticKeys);
        }

        $legacySpfInvalidCount = count(array_filter(
            $engineItems,
            fn (array $item) => ($item['semantic_key'] ?? null) === 'review_unsupported_spf_macro'
        ));
        $this->assertSame(1, $legacySpfInvalidCount);
    }

    public function test_persisted_recommendations_match_report_view_model_collection(): void
    {
        $spfInfo = FixtureLoader::input('spf-salesforce-partial');
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $dnsPayload['records']['SPF'] = ['status' => 'found', 'data' => $spfInfo['record']];
        $resultJson = [
            'dns' => [
                'score' => 73,
                'score_breakdown' => [
                    ['key' => 'spf', 'label' => 'SPF', 'earned' => 8, 'possible' => 20, 'status' => 'partial'],
                ],
                'records' => $dnsPayload['records'],
            ],
            'spf' => $spfInfo,
            'blacklist' => FixtureLoader::input('blacklist-clean'),
        ];

        $user = User::factory()->create();
        $domain = Domain::factory()->create(['domain' => 'salesforce.com', 'user_id' => $user->id]);
        $scan = \App\Models\Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'status' => 'finished',
            'score' => 73,
            'result_json' => $resultJson,
            'recommendations_json' => app(RecommendationEngineInterface::class)
                ->build($domain, new \App\Domain\EmailSecurity\DTO\ScanResultDTO($resultJson))
                ->items,
        ]);

        $this->actingAs($user);
        $report = app(ScanReportFactoryInterface::class)->build($scan->fresh(), $domain)->toArray();
        $reportKeys = array_column($report['recommendations'] ?? [], 'semantic_key');
        $persistedKeys = array_column($scan->recommendations_json, 'semantic_key');

        $this->assertSame($persistedKeys, $reportKeys);
        $this->assertSameSize($persistedKeys, array_unique($persistedKeys));
    }
}
