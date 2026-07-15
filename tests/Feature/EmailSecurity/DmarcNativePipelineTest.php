<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcRecordDiscovery;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcDnsQueryResult;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use App\Services\ScanRunner;
use App\Services\ScoreBreakdownService;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use Mockery;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\Support\EmailSecurity\FakeDmarcDnsResolver;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class DmarcNativePipelineTest extends TestCase
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

    public function test_missing_dmarc(): void
    {
        $execution = $this->runPipeline('dmarc-missing.test', null);
        $this->assertAnalysisContract($execution);
        $this->assertSame('none', $execution->resultJson['dmarc']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->dmarcEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_monitoring_none(): void
    {
        $execution = $this->runPipeline('dmarc-none.test', 'v=DMARC1; p=none; rua=mailto:a@b.com');
        $this->assertSame(12, $this->dmarcEarned($execution));
        $this->assertSame('none', $execution->resultJson['dmarc']['analysis']['policy']['effective_policy'] ?? null);
        $this->assertScoreInvariant($execution);
    }

    public function test_quarantine_full(): void
    {
        $execution = $this->runPipeline('dmarc-quar.test', 'v=DMARC1; p=quarantine; pct=100; rua=mailto:a@b.com');
        $this->assertSame(24, $this->dmarcEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_reject_full(): void
    {
        $execution = $this->runPipeline('dmarc-reject.test', 'v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com');
        $this->assertSame(30, $this->dmarcEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_reject_partial_pct(): void
    {
        $execution = $this->runPipeline('dmarc-reject-pct.test', 'v=DMARC1; p=reject; pct=25; rua=mailto:a@b.com');
        $this->assertSame(27, $this->dmarcEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_invalid_policy(): void
    {
        $execution = $this->runPipeline('dmarc-invalid.test', 'v=DMARC1; p=invalid; rua=mailto:a@b.com');
        $this->assertSame(0, $this->dmarcEarned($execution));
        $this->assertSame('permerror', $execution->resultJson['dmarc']['analysis']['protocol_status'] ?? null);
    }

    public function test_multiple_dmarc_records(): void
    {
        $record = 'v=DMARC1; p=quarantine';
        $payload = DmarcFixtureBuilder::dnsPayloadWithDmarc('dmarc-multi.test', $record);
        $payload['dmarc_txt_records'][] = [
            'host' => '_dmarc.dmarc-multi.test',
            'txt' => 'v=DMARC1; p=reject',
            'ttl' => 3600,
            'rr_index' => 1,
        ];
        $execution = $this->runPipeline('dmarc-multi.test', $record, dnsPayload: $payload);
        $this->assertSame(0, $this->dmarcEarned($execution));
        $this->assertSame('permerror', $execution->resultJson['dmarc']['analysis']['protocol_status'] ?? null);
    }

    public function test_missing_p_tag(): void
    {
        $execution = $this->runPipeline('dmarc-no-p.test', 'v=DMARC1; rua=mailto:a@b.com');
        $this->assertSame(0, $this->dmarcEarned($execution));
        $this->assertSame('permerror', $execution->resultJson['dmarc']['analysis']['protocol_status'] ?? null);
    }

    public function test_relaxed_alignment_defaults(): void
    {
        $execution = $this->runPipeline('dmarc-align.test', 'v=DMARC1; p=quarantine; rua=mailto:a@b.com');
        $alignment = $execution->resultJson['dmarc']['analysis']['alignment'] ?? [];
        $this->assertSame('relaxed', $alignment['dkim'] ?? null);
        $this->assertSame('relaxed', $alignment['spf'] ?? null);
    }

    public function test_strict_alignment(): void
    {
        $execution = $this->runPipeline('dmarc-strict.test', 'v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:a@b.com');
        $alignment = $execution->resultJson['dmarc']['analysis']['alignment'] ?? [];
        $this->assertSame('strict', $alignment['dkim'] ?? null);
        $this->assertSame('strict', $alignment['spf'] ?? null);
    }

    public function test_ruf_configured(): void
    {
        $execution = $this->runPipeline('dmarc-ruf.test', 'v=DMARC1; p=quarantine; rua=mailto:a@b.com; ruf=mailto:f@b.com');
        $this->assertTrue($execution->resultJson['dmarc']['analysis']['failure_reporting']['configured'] ?? false);
    }

    public function test_dns_timeout(): void
    {
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setTxt('_dmarc.dmarc-timeout.test', new DmarcDnsQueryResult(
            hostname: '_dmarc.dmarc-timeout.test',
            success: false,
            error: 'timeout',
            outcome: DmarcDnsQueryResult::OUTCOME_TIMEOUT,
        ));
        $payload = DmarcFixtureBuilder::dnsPayloadWithDmarc('dmarc-timeout.test', null);
        $payload['dmarc_txt_records'] = [];
        $execution = $this->runPipeline('dmarc-timeout.test', null, dnsPayload: $payload, resolver: $resolver);
        $this->assertSame(8, $this->dmarcEarned($execution));
        $this->assertContains(
            $execution->resultJson['dmarc']['analysis']['protocol_status'] ?? '',
            ['temperror', 'partially_evaluated'],
        );
    }

    public function test_mxscan_rua_absent_recommendation(): void
    {
        $domain = Domain::factory()->create([
            'domain' => 'dmarc-mxscan.test',
            'dmarc_token' => 'goldenfixturetoken',
        ]);
        $execution = $this->runPipeline(
            'dmarc-mxscan.test',
            'v=DMARC1; p=quarantine; rua=mailto:other@example.com',
            domain: $domain,
        );
        $keys = array_column($execution->recommendations, 'key');
        $this->assertContains('dmarc_mxscan_rua', $keys);
    }

    public function test_full_scan_entry(): void
    {
        $execution = $this->runPipeline(
            'dmarc-full.test',
            'v=DMARC1; p=quarantine; rua=mailto:a@b.com',
            options: ['dns' => true, 'spf' => true, 'blacklist' => true],
        );
        $this->assertArrayHasKey('spf', $execution->resultJson);
        $this->assertScoreInvariant($execution);
    }

    public function test_dns_only_entry(): void
    {
        $execution = $this->runPipeline(
            'dmarc-dns-only.test',
            'v=DMARC1; p=quarantine; rua=mailto:a@b.com',
            options: ['dns' => true, 'spf' => false, 'blacklist' => false],
        );
        $this->assertArrayHasKey('dmarc', $execution->resultJson);
        $this->assertArrayNotHasKey('spf', $execution->resultJson);
        $this->assertSame(24, $this->dmarcEarned($execution));
    }

    public function test_sync_runner_facts_include_dmarc_fields(): void
    {
        $execution = $this->runPipeline('dmarc-facts.test', 'v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com');
        $facts = ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson);
        $this->assertSame('valid', $facts['dmarc_protocol_status'] ?? null);
        $this->assertSame('reject', $facts['dmarc_effective_policy'] ?? null);
        $this->assertStringContainsString('v=DMARC1', (string) ($facts['dmarc_record'] ?? ''));
    }

    public function test_report_mapper_reads_analysis(): void
    {
        $execution = $this->runPipeline('dmarc-mapper.test', 'v=DMARC1; p=quarantine; rua=mailto:a@b.com');
        $card = (new ScanReportStatusMapper())->mapDmarc(
            $execution->resultJson['dns']['records']['DMARC'] ?? null,
            $execution->resultJson['dmarc'] ?? null,
        );
        $this->assertSame('quarantine', $card['policy'] ?? null);
    }

    public function test_analysis_reader_round_trip(): void
    {
        $execution = $this->runPipeline('dmarc-roundtrip.test', 'v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com');
        $analysis = DmarcAnalysisReader::analysis($execution->resultJson['dmarc'] ?? null);
        $this->assertSame('dmarc-native-v1', $analysis['version'] ?? null);
        $this->assertSame('reject', DmarcAnalysisReader::effectivePolicy($execution->resultJson['dmarc'] ?? null));
    }

    public function test_subdomain_sp_inheritance(): void
    {
        $domainName = 'mail.example.test';
        $orgRecord = 'v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@b.com';
        $payload = DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, null);
        $this->bindResolverMap([
            '_dmarc.' . $domainName => null,
            '_dmarc.example.test' => $orgRecord,
        ]);
        $execution = $this->runPipeline($domainName, null, dnsPayload: $payload);
        $policy = $execution->resultJson['dmarc']['analysis']['policy'] ?? [];
        $this->assertSame('organizational', $policy['policy_source'] ?? null);
        $this->assertSame('quarantine', $policy['effective_policy'] ?? null);
    }

    public function test_np_subdomain_nonexistent(): void
    {
        $domainName = 'nonexistent.example.test';
        $orgRecord = 'v=DMARC1; p=none; np=quarantine; rua=mailto:a@b.com';
        $payload = DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, null);
        $this->bindResolverMap([
            '_dmarc.' . $domainName => null,
            '_dmarc.example.test' => $orgRecord,
        ]);
        $execution = $this->runPipeline($domainName, null, dnsPayload: $payload);
        $this->assertSame('quarantine', $execution->resultJson['dmarc']['analysis']['policy']['effective_policy'] ?? null);
    }

    public function test_internal_rua(): void
    {
        $domainName = 'example.test';
        $record = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.test';
        $execution = $this->runPipeline($domainName, $record);
        $destinations = $execution->resultJson['dmarc']['analysis']['aggregate_reporting']['destinations'] ?? [];
        $this->assertNotEmpty($destinations);
        $this->assertTrue($destinations[0]['internal'] ?? false);
    }

    public function test_external_rua_authorized(): void
    {
        $domainName = 'example.test';
        $record = 'v=DMARC1; p=quarantine; rua=mailto:reports@external.com';
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setRecord('_dmarc.' . $domainName, $record);
        $resolver->setRecord('external.com._report._dmarc.' . $domainName, 'v=DMARC1');
        $execution = $this->runPipeline($domainName, $record, resolver: $resolver);
        $destinations = $execution->resultJson['dmarc']['analysis']['aggregate_reporting']['destinations'] ?? [];
        $this->assertSame('authorized', $destinations[0]['authorization_status'] ?? null);
    }

    public function test_external_rua_unauthorized(): void
    {
        $domainName = 'example.test';
        $record = 'v=DMARC1; p=quarantine; rua=mailto:reports@external.com';
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setRecord('_dmarc.' . $domainName, $record);
        $resolver->setRecord('external.com._report._dmarc.' . $domainName, null);
        $execution = $this->runPipeline($domainName, $record, resolver: $resolver);
        $analysis = $execution->resultJson['dmarc']['analysis'] ?? [];
        $this->assertSame(1, $analysis['external_authorization']['unauthorized_count'] ?? 0);
        $this->assertRecommendationContains($execution, 'dmarc_rua_unauthorized');
    }

    public function test_malformed_rua(): void
    {
        $execution = $this->runPipeline('dmarc-bad-rua.test', 'v=DMARC1; p=quarantine; rua=not-a-uri');
        $aggregate = $execution->resultJson['dmarc']['analysis']['aggregate_reporting'] ?? [];
        $this->assertFalse($aggregate['configured'] ?? true);
        $this->assertSame([], $aggregate['destinations'] ?? null);
    }

    public function test_multiple_rua_destinations(): void
    {
        $record = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com,mailto:c@d.com';
        $execution = $this->runPipeline('dmarc-multi-rua.test', $record);
        $destinations = $execution->resultJson['dmarc']['analysis']['aggregate_reporting']['destinations'] ?? [];
        $this->assertCount(2, $destinations);
    }

    public function test_dns_servfail(): void
    {
        $domainName = 'dmarc-servfail.test';
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setTxt('_dmarc.' . $domainName, new DmarcDnsQueryResult(
            hostname: '_dmarc.' . $domainName,
            success: false,
            error: 'servfail',
            outcome: DmarcDnsQueryResult::OUTCOME_SERVFAIL,
        ));
        $payload = DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, null);
        $execution = $this->runPipeline($domainName, null, dnsPayload: $payload, resolver: $resolver);
        $this->assertSame(8, $this->dmarcEarned($execution));
        $this->assertContains(
            $execution->resultJson['dmarc']['analysis']['protocol_status'] ?? '',
            ['temperror', 'partially_evaluated'],
        );
    }

    public function test_tree_walk_policy(): void
    {
        $domainName = 'mail.sub.example.test';
        $orgRecord = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com';
        $payload = DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, null);
        $this->bindResolverMap([
            '_dmarc.' . $domainName => null,
            '_dmarc.sub.example.test' => null,
            '_dmarc.example.test' => $orgRecord,
        ]);
        $execution = $this->runPipeline($domainName, null, dnsPayload: $payload);
        $discovery = $execution->resultJson['dmarc']['analysis']['discovery'] ?? [];
        $this->assertLessThanOrEqual(8, $discovery['queries_used'] ?? 99);
        $this->assertSame('quarantine', $execution->resultJson['dmarc']['analysis']['policy']['effective_policy'] ?? null);
    }

    public function test_mxscan_rua_present(): void
    {
        $domain = Domain::factory()->create([
            'domain' => 'dmarc-mxscan-present.test',
            'dmarc_token' => 'goldenfixturetoken',
        ]);
        $record = 'v=DMARC1; p=quarantine; rua=mailto:dmarc+goldenfixturetoken@mxscan.me';
        $execution = $this->runPipeline(
            'dmarc-mxscan-present.test',
            $record,
            domain: $domain,
        );
        $expectation = $execution->resultJson['dmarc']['analysis']['aggregate_reporting']['mxscan_expectation'] ?? [];
        $this->assertTrue($expectation['present'] ?? false);
    }

    public function test_public_scan_entry(): void
    {
        $domainName = 'public-entry.test';
        $record = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com';
        FixtureLoader::bindDnsCollector(DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, $record));
        $spfPayload = FixtureLoader::input('spf-configured');
        $spfResolver = Mockery::mock(SpfResolver::class);
        $spfResolver->shouldReceive('resolve')->andReturn(new SpfResultDTO(
            currentRecord: $spfPayload['record'],
            lookupsUsed: $spfPayload['lookups'],
            flattenedSpf: $spfPayload['flattened'],
            warnings: [],
            resolvedIps: [],
        ));
        $this->app->instance(SpfResolver::class, $spfResolver);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $response = $this->post(route('public.scan.run'), ['domain' => $domainName]);

        $response->assertOk();
        $response->assertViewHas('results', function (array $results): bool {
            return ($results['dmarc']['analysis']['version'] ?? null) === 'dmarc-native-v1';
        });
    }

    public function test_queued_run_full_scan_entry(): void
    {
        $domainName = 'queued-entry.test';
        $record = 'v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com';
        FixtureLoader::bindDnsCollector(DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, $record));
        $domain = Domain::factory()->create(['domain' => $domainName]);

        $job = new RunFullScan($domain->id, [
            'dns' => true,
            'spf' => false,
            'blacklist' => false,
            'monitoring' => false,
        ]);
        $job->handle(
            app(EmailSecurityScanService::class),
            app(\App\Domain\EmailSecurity\Contracts\ScanPersisterInterface::class),
            app(\App\Services\ScanReport\ScanFinalizer::class),
        );

        $scan = Scan::query()->where('domain_id', $domain->id)->latest('id')->first();
        $this->assertNotNull($scan);
        $facts = is_array($scan->facts_json) ? $scan->facts_json : [];
        $this->assertArrayHasKey('dmarc_protocol_status', $facts);
        $this->assertArrayHasKey('dmarc_effective_policy', $facts);
        $this->assertArrayHasKey('dmarc_record', $facts);
    }

    public function test_scheduled_scan_runner_entry(): void
    {
        $domainName = 'scheduled-entry.test';
        $record = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com';
        FixtureLoader::bindDnsCollector(DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, $record));
        $domain = Domain::factory()->create(['domain' => $domainName]);

        $scan = app(ScanRunner::class)->runSync($domain, [
            'dns' => true,
            'spf' => false,
            'blacklist' => false,
            'monitoring' => false,
        ]);
        $scan->refresh();

        $this->assertSame(
            'dmarc-native-v1',
            $scan->result_json['dmarc']['analysis']['version'] ?? null,
        );
    }

    /**
     * @param array<string, bool> $options
     */
    private function runPipeline(
        string $domainName,
        ?string $dmarcRecord,
        array $options = ['dns' => true, 'spf' => false, 'blacklist' => false],
        ?array $dnsPayload = null,
        ?FakeDmarcDnsResolver $resolver = null,
        ?Domain $domain = null,
    ): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO {
        $dnsPayload ??= DmarcFixtureBuilder::dnsPayloadWithDmarc($domainName, $dmarcRecord);
        FixtureLoader::bindDnsCollector($dnsPayload);

        if ($resolver !== null) {
            $this->app->instance(DmarcDnsResolverInterface::class, $resolver);
            $this->app->instance(DmarcRecordDiscovery::class, new DmarcRecordDiscovery($resolver));
            $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
        }

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

    private function dmarcEarned(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): int
    {
        $row = $this->scoreBreakdown->findRow(
            $execution->resultJson['dns']['score_breakdown'] ?? [],
            'dmarc',
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
            'dmarc-native-v1',
            $execution->resultJson['dmarc']['analysis']['version'] ?? null,
        );
    }

    /**
     * @param array<string, ?string> $hostnameToRecord
     */
    private function bindResolverMap(array $hostnameToRecord): void
    {
        $resolver = new FakeDmarcDnsResolver();
        foreach ($hostnameToRecord as $hostname => $record) {
            $resolver->setRecord($hostname, $record);
        }
        $this->app->instance(DmarcDnsResolverInterface::class, $resolver);
        $this->app->instance(DmarcRecordDiscovery::class, new DmarcRecordDiscovery($resolver));
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
    }

    private function assertRecommendationContains(
        \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution,
        string $key,
    ): void {
        $keys = array_column($execution->recommendations, 'key');
        $this->assertContains($key, $keys);
    }
}
