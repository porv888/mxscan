<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use App\Services\ScanRunner;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\DkimDnsMockResolver;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class DkimNativePipelineTest extends TestCase
{
    use RefreshDatabase;

    private ScoreBreakdownService $scoreBreakdown;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
        $this->scoreBreakdown = new ScoreBreakdownService();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_valid_rsa_2048_scores_twenty_points(): void
    {
        $execution = $this->runPipeline(
            'dkim-valid.test',
            resolver: $this->resolverWithKey('s1', 'dkim-valid.test'),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false, 'dkim_selector' => 's1'],
        );

        $this->assertAnalysisContract($execution);
        $this->assertSame(20, $this->dkimEarned($execution));
        $this->assertSame('valid', $execution->resultJson['dkim']['analysis']['protocol_status'] ?? null);
        $this->assertScoreInvariant($execution);
    }

    public function test_catalog_only_miss_scores_ten_points(): void
    {
        $execution = $this->runPipeline(
            'dkim-catalog-miss.test',
            resolver: new DkimDnsMockResolver(),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false],
        );

        $this->assertSame(10, $this->dkimEarned($execution));
        $this->assertSame('none', $execution->resultJson['dkim']['analysis']['protocol_status'] ?? null);
        $this->assertSame('catalog_only', $execution->resultJson['dkim']['analysis']['selector_coverage']['coverage_type'] ?? null);
        $this->assertScoreInvariant($execution);
    }

    public function test_no_selector_available_scores_eight_points(): void
    {
        config(['dkim.selectors' => [], 'dkim.catalog_limit' => 0]);

        $execution = $this->runPipeline(
            'dkim-no-selector.test',
            resolver: new DkimDnsMockResolver(),
            options: ['dkim' => true, 'dns' => false, 'spf' => false, 'blacklist' => false],
        );

        $this->assertSame(8, $this->dkimEarned($execution));
        $this->assertSame(
            'partially_evaluated',
            $execution->resultJson['dkim']['analysis']['protocol_status'] ?? null,
        );
        $this->assertFalse($execution->resultJson['dkim']['analysis']['selector_coverage']['selectors_available'] ?? true);
        $this->assertScoreInvariant($execution);
    }

    public function test_explicit_selector_from_signature(): void
    {
        $signature = 'v=1; a=rsa-sha256; d=example.com; s=mail2024; c=relaxed/relaxed;';
        $resolver = $this->resolverWithKey('mail2024', 'dkim-signature.test');
        $execution = $this->runPipeline(
            'dkim-signature.test',
            resolver: $resolver,
            options: [
                'dkim' => true,
                'dns' => false,
                'spf' => false,
                'blacklist' => false,
                'dkim_signature' => $signature,
            ],
        );

        $this->assertSame(20, $this->dkimEarned($execution));
        $this->assertSame('signature', $execution->resultJson['dkim']['analysis']['selector_coverage']['coverage_type'] ?? null);
        $this->assertContains('mail2024._domainkey.dkim-signature.test', $resolver->queries());
    }

    public function test_dkim_dns_compat_merged_into_dns_records(): void
    {
        $execution = $this->runPipeline(
            'dkim-compat.test',
            resolver: $this->resolverWithKey('google', 'dkim-compat.test'),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false, 'dkim_selector' => 'google'],
        );

        $dkimRecord = $execution->resultJson['dns']['records']['DKIM'] ?? null;
        $this->assertIsArray($dkimRecord);
        $this->assertSame('found', $dkimRecord['status'] ?? null);
        $this->assertNotEmpty($dkimRecord['data'] ?? null);
    }

    public function test_signing_verified_is_always_false(): void
    {
        $execution = $this->runPipeline(
            'dkim-signing.test',
            resolver: $this->resolverWithKey('s1', 'dkim-signing.test'),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false, 'dkim_selector' => 's1'],
        );

        $this->assertFalse($execution->resultJson['dkim']['analysis']['signing_verified'] ?? true);
    }

    public function test_dkim_verify_recommendation_emitted(): void
    {
        $execution = $this->runPipeline(
            'dkim-rec.test',
            resolver: $this->resolverWithKey('s1', 'dkim-rec.test'),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false, 'dkim_selector' => 's1'],
        );

        $keys = array_column($execution->recommendations, 'key');
        $this->assertContains('dkim_verify', $keys);
    }

    public function test_report_mapper_reads_native_analysis(): void
    {
        $execution = $this->runPipeline(
            'dkim-mapper.test',
            resolver: $this->resolverWithKey('s1', 'dkim-mapper.test'),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false, 'dkim_selector' => 's1'],
        );

        $dkimSection = $execution->resultJson['dkim'] ?? [];
        $dkimSection = $execution->resultJson['dkim'] ?? [];
        $analysis = DkimAnalysisReader::analysis($dkimSection);
        $this->assertIsArray($analysis);
        $this->assertSame('dkim-native-v1', $analysis['version'] ?? null);
        $this->assertSame('valid', $analysis['protocol_status'] ?? null);

        $card = (new ScanReportStatusMapper())->mapDkim(
            $execution->resultJson['dns']['records']['DKIM'] ?? null,
            $dkimSection,
        );

        $this->assertIsArray($card);
        $this->assertArrayHasKey('status', $card);
    }

    public function test_sync_facts_include_dkim_fields(): void
    {
        $execution = $this->runPipeline(
            'dkim-facts.test',
            resolver: $this->resolverWithKey('s1', 'dkim-facts.test'),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false, 'dkim_selector' => 's1'],
        );

        $facts = ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson, $execution->spfRawResult);
        $this->assertSame('valid', $facts['dkim_protocol_status'] ?? null);
    }

    public function test_queued_run_full_scan_dkim_only_entry(): void
    {
        $domainName = 'dkim-queued.test';
        $domain = Domain::factory()->create(['domain' => $domainName]);
        config(['dkim.selectors' => [], 'dkim.catalog_limit' => 0]);
        $this->bindResolver($this->resolverWithKey('queued', $domainName));

        $job = new RunFullScan($domain->id, [
            'dns' => false,
            'spf' => false,
            'blacklist' => false,
            'dkim' => true,
            'dkim_selector' => 'queued',
            'monitoring' => false,
        ]);
        $job->handle(
            app(EmailSecurityScanService::class),
            app(\App\Domain\EmailSecurity\Contracts\ScanPersisterInterface::class),
            app(\App\Services\ScanReport\ScanFinalizer::class),
        );

        $scan = Scan::query()->where('domain_id', $domain->id)->latest('id')->first();
        $this->assertNotNull($scan);
        $this->assertSame('dkim-native-v1', $scan->result_json['dkim']['analysis']['version'] ?? null);
    }

    public function test_scheduled_scan_runner_dkim_entry(): void
    {
        $domainName = 'dkim-scheduled.test';
        $domain = Domain::factory()->create(['domain' => $domainName]);
        $this->bindResolver($this->resolverWithKey('s1', $domainName));

        $scan = app(ScanRunner::class)->runSync($domain, [
            'dns' => true,
            'spf' => false,
            'blacklist' => false,
            'dkim_selector' => 's1',
            'monitoring' => false,
        ]);
        $scan->refresh();

        $this->assertSame('dkim-native-v1', $scan->result_json['dkim']['analysis']['version'] ?? null);
    }

    public function test_analysis_reader_reads_persisted_payload(): void
    {
        $execution = $this->runPipeline(
            'dkim-reader.test',
            resolver: $this->resolverWithKey('s1', 'dkim-reader.test'),
            options: ['dns' => true, 'spf' => false, 'blacklist' => false, 'dkim_selector' => 's1'],
        );

        $section = $execution->resultJson['dkim'] ?? [];
        $this->assertSame('valid', DkimAnalysisReader::protocolStatus($section));
        $this->assertSame('dkim-native-v1', DkimAnalysisReader::analysis($section)['version'] ?? null);
    }

    /**
     * @param array<string, bool|string|null> $options
     */
    private function runPipeline(
        string $domainName,
        DkimDnsMockResolver $resolver,
        array $options = ['dns' => true, 'spf' => false, 'blacklist' => false],
        ?Domain $domain = null,
    ): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO {
        FixtureLoader::bindDnsCollector(FixtureLoader::input('dns-bundled-full'));
        $this->bindResolver($resolver);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $domain ??= Domain::factory()->create(['domain' => $domainName]);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
        ]);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray($options),
            microtime(true),
        );
    }

    private function bindResolver(DkimDnsMockResolver $resolver): void
    {
        $this->app->instance(DkimDnsResolverInterface::class, $resolver);
    }

    private function resolverWithKey(string $selector, string $domain): DkimDnsMockResolver
    {
        $resolver = new DkimDnsMockResolver();
        $hostname = "{$selector}._domainkey.{$domain}";
        $resolver->setTxt($hostname, new DkimDnsQueryResult(
            hostname: $hostname,
            success: true,
            reconstructedTxt: [FixtureLoader::TEST_RSA_2048_DKIM_RECORD],
            ttl: 3600,
            outcome: DkimDnsQueryResult::OUTCOME_ANSWER,
        ));

        return $resolver;
    }

    private function dkimEarned(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): int
    {
        $row = $this->scoreBreakdown->findRow(
            $execution->resultJson['dns']['score_breakdown'] ?? [],
            'dkim',
        );

        return (int) ($row['earned'] ?? -1);
    }

    private function assertScoreInvariant(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): void
    {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        $sum = $this->scoreBreakdown->totalEarned($breakdown);
        $this->assertSame($execution->score, $sum);
        $this->assertSame($execution->score, $execution->resultJson['dns']['score'] ?? null);
    }

    private function assertAnalysisContract(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): void
    {
        $this->assertSame(
            'dkim-native-v1',
            $execution->resultJson['dkim']['analysis']['version'] ?? null,
        );
    }
}
