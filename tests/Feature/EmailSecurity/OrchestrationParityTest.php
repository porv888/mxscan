<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\Scan;

use App\Services\EmailSecurityScanService;
use App\Services\ScanRunner;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Mockery;
use Tests\Support\EmailSecurity\BindsFakeBlacklistDns;
use Tests\Support\EmailSecurity\CertificateTestProbeFactory;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\JsonParityNormalizer;
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

    public function test_scan_runner_persists_native_spf_scan(): void
    {
        $this->bindFixtureServices('parity-runner.test');
        $runnerDomain = Domain::factory()->create(['domain' => 'parity-runner.test']);
        $scan = app(ScanRunner::class)->runSync($runnerDomain, [
            'dns' => true,
            'spf' => true,
            'blacklist' => true,
            'monitoring' => false,
        ]);
        $scan->refresh();

        $this->assertSame('finished', $scan->status);
        $this->assertSame('spf-native-v1', $scan->result_json['spf']['analysis']['version'] ?? null);
        $this->assertSame(
            $scan->score,
            (new ScoreBreakdownService())->totalEarned($scan->result_json['dns']['score_breakdown'] ?? [])
        );
    }

    public function test_email_security_service_produces_native_spf_scan(): void
    {
        $this->bindFixtureServices('parity-direct.test');
        $domain = Domain::factory()->create(['domain' => 'parity-direct.test']);
        $direct = $this->runDirectPipeline($domain);

        $this->assertSame('spf-native-v1', $direct->resultJson['spf']['analysis']['version'] ?? null);
        $this->assertSame(
            $direct->score,
            (new ScoreBreakdownService())->totalEarned($direct->resultJson['dns']['score_breakdown'] ?? [])
        );
    }

    public function test_async_job_persists_same_core_json_as_sync_pipeline(): void
    {
        Queue::fake();
        $this->bindFixtureServices('async-sync.test');

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
            ScanPayloadBuilder::buildFactsForAsyncJob($syncScan->result_json ?? []),
            $asyncScan->facts_json
        );
    }

    public function test_async_job_facts_include_dmarc_fields(): void
    {
        $this->bindFixtureServices('async-dmarc-facts.test');

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

    private function bindFixtureServices(string $domainName): void
    {
        foreach ([
            \App\Domain\EmailSecurity\Checks\CheckRegistry::class,
            \App\Domain\EmailSecurity\Checks\SPF\SpfCheck::class,
            \App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluator::class,
            \App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver::class,
            \App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery::class,
            \App\Domain\EmailSecurity\Checks\DKIM\DkimCheck::class,
            \App\Domain\EmailSecurity\Checks\DKIM\DkimConfirmedSelectorRepository::class,
            \App\Domain\EmailSecurity\Checks\DMARC\DmarcCheck::class,
            \App\Domain\EmailSecurity\Checks\Mx\MxCheck::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck::class,
            \App\Services\EmailSecurityScanService::class,
            \App\Services\ScanRunner::class,
        ] as $class) {
            $this->app->forgetInstance($class);
        }

        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $spfPayload = FixtureLoader::input('spf-configured');

        FixtureLoader::bindDnsCollector($dnsPayload);
        FixtureLoader::bindDkimResolver($domainName);
        FixtureLoader::bindMtaStsFixtures();
        FixtureLoader::bindTlsRptFixtures();
        FixtureLoader::bindBimiFixtures();
        FixtureLoader::bindMxFixtures($dnsPayload, $domainName);
        CertificateTestProbeFactory::bindFakeProbes();
        FixtureLoader::bindNativeSpfDns($domainName, $spfPayload['record']);

        $this->bindFakeBlacklistDns();
    }
}
