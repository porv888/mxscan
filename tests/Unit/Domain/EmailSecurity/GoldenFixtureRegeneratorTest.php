<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;
use App\Domain\EmailSecurity\Recommendations\RecommendationEngine;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;

use App\Services\EmailSecurityScanService;
use App\Services\ScanTrendService;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\BindsFakeBlacklistDns;
use Tests\Support\EmailSecurity\CertificateTestProbeFactory;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\JsonParityNormalizer;
use Tests\TestCase;

/**
 * @group golden-regenerate
 */
class GoldenFixtureRegeneratorTest extends TestCase
{
    use BindsFakeBlacklistDns;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['email-security.spf_engine' => 'legacy']);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_regenerate_sync_golden_fixture(): void
    {
        if (! getenv('REGEN_GOLDEN')) {
            $this->markTestSkipped('Set REGEN_GOLDEN=1 to regenerate golden fixtures.');
        }

        $this->writeSyncAsync('example.test', 'goldenfixturetoken', 'sync/full-scan', true);
        $this->assertTrue(true);
    }

    public function test_regenerate_async_golden_fixture(): void
    {
        if (! getenv('REGEN_GOLDEN')) {
            $this->markTestSkipped('Set REGEN_GOLDEN=1 to regenerate golden fixtures.');
        }

        $this->writeSyncAsync('example.test', 'goldenfixturetoken', 'async/full-scan', false);
        $this->assertTrue(true);
    }

    public function test_regenerate_report_view_golden_fixture(): void
    {
        if (! getenv('REGEN_GOLDEN')) {
            $this->markTestSkipped('Set REGEN_GOLDEN=1 to regenerate golden fixtures.');
        }

        $this->writeReportView();
        $this->assertTrue(true);
    }

    private function writeSyncAsync(string $domainName, string $dmarcToken, string $fixturePath, bool $syncFacts): void
    {
        $execution = $this->runExamplePipeline($domainName, $dmarcToken);
        $domain = Domain::query()->where('domain', $domainName)->latest('id')->first();

        $facts = $syncFacts
            ? ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson, $execution->spfRawResult)
            : ScanPayloadBuilder::buildFactsForAsyncJob($execution->resultJson);

        $keys = array_column(
            app(RecommendationEngine::class)->build($domain, new ScanResultDTO($execution->resultJson))->items,
            'key',
        );

        $payload = [
            'score' => $execution->score,
            'result_json' => JsonParityNormalizer::normalize($execution->resultJson),
            'facts_json' => $facts,
            'recommendation_keys' => $keys,
        ];

        $this->writeFixture("expected/{$fixturePath}", $payload);
    }

    private function writeReportView(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $this->mock(ScanTrendService::class, function ($mock): void {
            $mock->shouldReceive('getDomainTrend')->andReturn([
                'labels' => ['Jan', 'Feb'],
                'scores' => [70, 75],
            ]);
        });

        $execution = $this->runScenarioPipeline($user);
        $domain = Domain::first();
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'finished',
            'type' => 'full',
            'score' => $execution->score,
            'result_json' => $execution->resultJson,
            'recommendations_json' => $execution->recommendations,
        ]);

        $viewModel = app(ScanReportFactoryInterface::class)->build($scan, $domain)->toArray();

        $payload = [
            'score' => $viewModel['score'],
            'recommendation_keys' => array_column($viewModel['recommendations'] ?? [], 'key'),
            'status_card_labels' => [
                'blacklist' => $viewModel['statusCards']['blacklist']['label'] ?? null,
                'spf' => $viewModel['statusCards']['spf']['card_label'] ?? null,
                'dmarc' => $viewModel['statusCards']['dmarc']['status'] ?? null,
            ],
            'result_json' => JsonParityNormalizer::normalize($viewModel['resultData'] ?? []),
        ];

        $this->writeFixture('expected/report-view/full-scan', $payload);
    }

    private function runExamplePipeline(string $domainName, string $dmarcToken): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO
    {
        $this->resetPipelineContainer();

        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $spfPayload = FixtureLoader::input('spf-configured');
        $blacklistPayload = FixtureLoader::input('blacklist-clean');

        FixtureLoader::bindDnsCollector($dnsPayload);
        FixtureLoader::bindDkimResolver($domainName);
        FixtureLoader::bindMtaStsFixtures();
        FixtureLoader::bindTlsRptFixtures();
        FixtureLoader::bindBimiFixtures();
        FixtureLoader::bindMxFixtures($dnsPayload, $domainName);
        CertificateTestProbeFactory::bindFakeProbes();

        $spfResolver = Mockery::mock(SpfResolver::class);
        $spfResolver->shouldReceive('resolve')->andReturn(new SpfResultDTO(
            currentRecord: $spfPayload['record'],
            lookupsUsed: $spfPayload['lookups'],
            flattenedSpf: $spfPayload['flattened'],
            warnings: [],
            resolvedIps: [],
        ));
        $this->app->instance(SpfResolver::class, $spfResolver);

        $this->bindFakeBlacklistDns();

        $domain = Domain::factory()->create([
            'domain' => $domainName,
            'dmarc_token' => $dmarcToken,
        ]);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
        ]);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => true, 'monitoring' => false]),
            microtime(true),
        );
    }

    private function runScenarioPipeline(User $user): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO
    {
        $this->resetPipelineContainer();

        $spfPayload = FixtureLoader::input('spf-configured');
        $blacklistPayload = FixtureLoader::input('blacklist-clean');

        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        FixtureLoader::bindDnsCollector($dnsPayload);
        FixtureLoader::bindDkimResolver('scenario.test');
        FixtureLoader::bindMtaStsFixtures();
        FixtureLoader::bindTlsRptFixtures();
        FixtureLoader::bindBimiFixtures();
        FixtureLoader::bindMxFixtures($dnsPayload, 'scenario.test');

        $spfResolver = Mockery::mock(SpfResolver::class);
        $spfResolver->shouldReceive('resolve')->andReturn(new SpfResultDTO(
            currentRecord: $spfPayload['record'],
            lookupsUsed: $spfPayload['lookups'],
            flattenedSpf: $spfPayload['flattened'],
            warnings: [],
            resolvedIps: [],
        ));
        $this->app->instance(SpfResolver::class, $spfResolver);

        $this->bindFakeBlacklistDns();

        $domain = Domain::factory()->create([
            'domain' => 'scenario.test',
            'user_id' => $user->id,
            'dmarc_token' => 'goldenfixturetoken',
        ]);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
        ]);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => true, 'monitoring' => false]),
            microtime(true),
        );
    }

    private function resetPipelineContainer(): void
    {
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\SpfAnalysisCheck::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Mx\MxCheck::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Mx\MxAnalysisService::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface::class);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function writeFixture(string $relativePath, array $payload): void
    {
        $path = base_path("tests/Fixtures/EmailSecurity/{$relativePath}.json");
        file_put_contents(
            $path,
            json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n",
        );
        fwrite(STDOUT, "Wrote {$path}\n");
    }
}
