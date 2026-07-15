<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\SPF\Compatibility\SpfNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\SPF\Recommendations\SpfRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\Dns\DnsClient;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\EmailSecurity\FakeDnsClient;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class NativeSpfRolloutVerificationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
    }

    public function test_native_scan_persists_versioned_analysis_contract(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        FixtureLoader::bindDnsCollector($dnsPayload);
        FixtureLoader::bindNativeSpfDns('rollout-native.test', $dnsPayload['records']['SPF']['data'] ?? 'v=spf1 a mx -all');

        $domain = Domain::factory()->create(['domain' => 'rollout-native.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $execution = app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => false]),
            microtime(true),
        );

        $spf = $execution->resultJson['spf'];
        $analysis = $spf['analysis'] ?? null;

        $this->assertIsArray($analysis);
        $this->assertSame(SpfNativeAnalysisPayload::VERSION, $analysis['version']);
        $this->assertSame('valid', $analysis['protocol_status']);
        $this->assertSame(SpfTerminalPolicy::HARD_FAIL, $analysis['terminal_policy']);
        $this->assertArrayHasKey('evaluation_completeness', $analysis);
        $this->assertArrayHasKey('dependencies', $analysis);
        $this->assertArrayNotHasKey('terminal_policy', $spf);
        $this->assertSame($analysis['protocol_status'], $spf['protocol_status']);
        $this->assertSame($execution->score, (new ScoreBreakdownService())->totalEarned($execution->resultJson['dns']['score_breakdown'] ?? []));
    }

    public function test_historical_legacy_spf_payload_renders_safely(): void
    {
        $spfInfo = FixtureLoader::input('spf-configured');
        $mapper = new ScanReportStatusMapper();
        $card = $mapper->mapSpf(['status' => 'found', 'data' => $spfInfo['record']], $spfInfo);

        $this->assertSame('pass', $card['state']);
        $this->assertNull(\App\Domain\EmailSecurity\Checks\SPF\Support\SpfAnalysisReader::terminalPolicy($spfInfo));

        $items = (new SpfRecommendationEvaluator())->evaluate(
            ['status' => 'found', 'data' => $spfInfo['record']],
            $card,
            $spfInfo,
        );

        $this->assertFalse(collect($items)->contains(fn ($item) => ($item['semantic_key'] ?? '') === 'review_weak_terminal_policy'));
    }
}
