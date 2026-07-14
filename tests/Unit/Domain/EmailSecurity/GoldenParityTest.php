<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Checks\BundledDnsChecksAdapter;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Reporting\ScanResultNormalizer;
use App\Domain\EmailSecurity\Scoring\LegacyDnsScoreCalculator;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Domain\EmailSecurity\Support\ScanResultAssembler;
use App\Domain\EmailSecurity\Support\ScoringInputFactory;
use App\Domain\EmailSecurity\Recommendations\RecommendationEngine;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\BlacklistChecker;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\JsonParityNormalizer;
use Tests\TestCase;

class GoldenParityTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_normalized_pipeline_matches_legacy_result_json_projection(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $spfPayload = FixtureLoader::input('spf-configured');
        $blacklistPayload = FixtureLoader::input('blacklist-clean');

        $legacySections = [
            'dns' => $dnsPayload,
            'spf' => $spfPayload,
            'blacklist' => $blacklistPayload,
        ];

        $assembler = new ScanResultAssembler();
        $legacyResult = $assembler->assemble($legacySections);

        $domain = Domain::factory()->create(['domain' => 'example.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);
        $context = CheckContextDTO::fromExecution($domain, $scan, ScanOptionsDTO::fromArray([]));
        $dns = FixtureLoader::dnsCollection();
        $bundled = (new BundledDnsChecksAdapter())->adapt($dns);

        $native = [
            'spf' => (new \App\Domain\EmailSecurity\DTO\CheckResultDTO('spf', $spfPayload['status'], $spfPayload)),
            'blacklist' => (new \App\Domain\EmailSecurity\DTO\CheckResultDTO('blacklist', 'clean', $blacklistPayload)),
        ];

        $normalized = $assembler->assembleNormalized($context, $dns, $bundled, $native);
        $projected = $assembler->toScanResultDTO($normalized);

        $this->assertSame(
            JsonParityNormalizer::normalize($legacyResult->toArray()),
            JsonParityNormalizer::normalize($projected->toArray())
        );
    }

    public function test_scoring_input_preserves_legacy_score(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $assembler = new ScanResultAssembler();
        $domain = Domain::factory()->create(['domain' => 'example.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);
        $context = CheckContextDTO::fromExecution($domain, $scan, ScanOptionsDTO::fromArray([]));
        $dns = FixtureLoader::dnsCollection();
        $normalized = $assembler->assembleNormalized($context, $dns, (new BundledDnsChecksAdapter())->adapt($dns), []);

        $calculator = new LegacyDnsScoreCalculator(new ScoreBreakdownService());
        $score = $calculator->calculate((new ScoringInputFactory())->from($normalized));

        $this->assertSame(75, $score->total);
    }

    public function test_scan_result_normalizer_round_trip_is_stable(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $sections = [
            'dns' => $dnsPayload,
            'spf' => FixtureLoader::input('spf-configured'),
            'blacklist' => FixtureLoader::input('blacklist-clean'),
        ];

        $assembler = new ScanResultAssembler();
        $scanResult = $assembler->assemble($sections);
        $normalizer = new ScanResultNormalizer();
        $normalized = $normalizer->normalize($scanResult);
        $roundTrip = $assembler->toScanResultDTO($normalized);

        $this->assertSame(
            JsonParityNormalizer::normalize($scanResult->toArray()),
            JsonParityNormalizer::normalize($roundTrip->toArray())
        );
    }

    public function test_full_pipeline_matches_sync_golden_fixture(): void
    {
        $expected = FixtureLoader::expected('sync/full-scan');
        $execution = $this->runPipelineWithFixtures();

        $facts = ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson, $execution->spfRawResult);
        $keys = array_column(
            app(RecommendationEngine::class)->build(
                Domain::first(),
                new \App\Domain\EmailSecurity\DTO\ScanResultDTO($execution->resultJson)
            )->items,
            'key'
        );

        $this->assertSame($expected['score'], $execution->score);
        $this->assertSame(
            JsonParityNormalizer::normalize($expected['result_json']),
            JsonParityNormalizer::normalize($execution->resultJson)
        );
        $this->assertSame($expected['facts_json'], $facts);
        $this->assertSame($expected['recommendation_keys'], $keys);
    }

    public function test_full_pipeline_matches_async_golden_fixture(): void
    {
        $expected = FixtureLoader::expected('async/full-scan');
        $execution = $this->runPipelineWithFixtures();

        $facts = ScanPayloadBuilder::buildFactsForAsyncJob($execution->resultJson);
        $keys = array_column(
            app(RecommendationEngine::class)->build(
                Domain::first(),
                new \App\Domain\EmailSecurity\DTO\ScanResultDTO($execution->resultJson)
            )->items,
            'key'
        );

        $this->assertSame($expected['score'], $execution->score);
        $this->assertSame(
            JsonParityNormalizer::normalize($expected['result_json']),
            JsonParityNormalizer::normalize($execution->resultJson)
        );
        $this->assertSame($expected['facts_json'], $facts);
        $this->assertSame($expected['recommendation_keys'], $keys);
    }

    private function runPipelineWithFixtures(): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $spfPayload = FixtureLoader::input('spf-configured');
        $blacklistPayload = FixtureLoader::input('blacklist-clean');

        FixtureLoader::bindDnsCollector($dnsPayload);

        $spfResolver = Mockery::mock(SpfResolver::class);
        $spfResolver->shouldReceive('resolve')->andReturn(new SpfResultDTO(
            currentRecord: $spfPayload['record'],
            lookupsUsed: $spfPayload['lookups'],
            flattenedSpf: $spfPayload['flattened'],
            warnings: [],
            resolvedIps: [],
        ));
        $this->app->instance(SpfResolver::class, $spfResolver);

        $domain = Domain::factory()->create(['domain' => 'example.test']);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
        ]);

        $blacklistChecker = Mockery::mock(BlacklistChecker::class);
        $blacklistChecker->shouldReceive('checkDomain')->andReturn([]);
        $blacklistChecker->shouldReceive('getScanSummary')->andReturn($blacklistPayload);
        $this->app->instance(BlacklistChecker::class, $blacklistChecker);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => true, 'monitoring' => false]),
            microtime(true),
        );
    }
}
