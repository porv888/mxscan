<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\Scan;

use App\Services\EmailSecurityScanService;
use App\Services\ScanRunner;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Mockery;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\JsonParityNormalizer;
use Tests\Support\EmailSecurity\BindsFakeBlacklistDns;
use Tests\TestCase;

class OrchestrationParityTest extends TestCase
{
    use BindsFakeBlacklistDns;
    use RefreshDatabase;

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_scan_runner_and_email_security_service_produce_equivalent_persisted_json(): void
    {
        $this->bindFixtureServices();

        $domain = Domain::factory()->create(['domain' => 'runner-parity.test']);
        $runner = app(ScanRunner::class);
        $scan = $runner->runSync($domain, ['dns' => true, 'spf' => true, 'blacklist' => true, 'monitoring' => false]);
        $scan->refresh();

        $direct = $this->runDirectPipeline($domain);

        $this->assertSame($direct->score, $scan->score);
        $this->assertSame(
            JsonParityNormalizer::normalize($direct->resultJson),
            JsonParityNormalizer::normalize($scan->result_json ?? [])
        );
        $this->assertSame(
            JsonParityNormalizer::normalize($direct->recommendations),
            JsonParityNormalizer::normalize($scan->recommendations_json ?? [])
        );
    }

    public function test_async_job_persists_same_core_json_as_sync_pipeline(): void
    {
        Queue::fake();
        $this->bindFixtureServices();

        $domain = Domain::factory()->create(['domain' => 'async-sync.test']);
        $syncScan = app(ScanRunner::class)->runSync($domain, [
            'dns' => true,
            'spf' => true,
            'blacklist' => true,
            'monitoring' => false,
        ]);

        $job = new RunFullScan($domain->id, [
            'dns' => true,
            'spf' => true,
            'blacklist' => true,
            'monitoring' => false,
        ]);
        $job->handle(
            app(EmailSecurityScanService::class),
            app(\App\Domain\EmailSecurity\Contracts\ScanPersisterInterface::class),
            app(\App\Services\ScanReport\ScanFinalizer::class),
        );

        $asyncScan = Scan::query()->where('domain_id', $domain->id)->where('id', '!=', $syncScan->id)->latest('id')->first();
        $syncScan->refresh();
        $asyncScan->refresh();

        $this->assertSame($syncScan->score, $asyncScan->score);
        $this->assertSame(
            JsonParityNormalizer::normalize($syncScan->result_json ?? []),
            JsonParityNormalizer::normalize($asyncScan->result_json ?? [])
        );
        $this->assertSame(
            JsonParityNormalizer::normalize($syncScan->recommendations_json ?? []),
            JsonParityNormalizer::normalize($asyncScan->recommendations_json ?? [])
        );
        $this->assertSame(
            ScanPayloadBuilder::buildFactsForAsyncJob($syncScan->result_json ?? []),
            $asyncScan->facts_json
        );
    }

    public function test_async_job_facts_include_dmarc_fields(): void
    {
        $this->bindFixtureServices();

        $domain = Domain::factory()->create(['domain' => 'async-dmarc-facts.test']);
        $job = new RunFullScan($domain->id, [
            'dns' => true,
            'spf' => true,
            'blacklist' => true,
            'monitoring' => false,
        ]);
        $job->handle(
            app(EmailSecurityScanService::class),
            app(\App\Domain\EmailSecurity\Contracts\ScanPersisterInterface::class),
            app(\App\Services\ScanReport\ScanFinalizer::class),
        );

        $scan = Scan::query()->where('domain_id', $domain->id)->latest('id')->first();
        $facts = is_array($scan?->facts_json) ? $scan->facts_json : [];

        $this->assertArrayHasKey('dmarc_record', $facts);
        $this->assertArrayHasKey('dmarc_protocol_status', $facts);
        $this->assertArrayHasKey('dmarc_effective_policy', $facts);
    }

    private function runDirectPipeline(Domain $domain): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO
    {
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

    private function bindFixtureServices(): void
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

        $this->bindFakeBlacklistDns();
    }
}
