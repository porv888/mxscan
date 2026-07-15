<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;

use App\Services\EmailSecurityScanService;
use App\Services\Dns\DnsResult;
use App\Services\ScanTrendService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\BindsFakeBlacklistDns;
use Tests\Support\EmailSecurity\CertificateTestProbeFactory;
use Tests\Support\EmailSecurity\FakeDnsClient;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\JsonParityNormalizer;
use Tests\TestCase;

class GoldenParityScenariosTest extends TestCase
{
    use BindsFakeBlacklistDns;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
        $this->bindFakeBlacklistDns();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_spf_missing_produces_sync_facts_with_no_record_string(): void
    {
        $execution = $this->runPipeline(
            spfRecord: null,
            spfLookups: 0,
            blacklist: FixtureLoader::input('blacklist-clean'),
        );

        $facts = ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson, $execution->spfRawResult);

        $this->assertSame('No SPF record found', $facts['spf_record']);
        $this->assertSame(0, $facts['spf_lookups']);
    }

    public function test_spf_configured_preserves_lookup_and_record_parity(): void
    {
        $spfPayload = FixtureLoader::input('spf-configured');
        $execution = $this->runPipeline(
            spfRecord: $spfPayload['record'],
            spfLookups: $spfPayload['lookups'],
            blacklist: FixtureLoader::input('blacklist-clean'),
            flattenedSpf: $spfPayload['flattened'],
        );

        $this->assertSame($spfPayload['record'], $execution->resultJson['spf']['record'] ?? null);
        $this->assertSame('spf-native-v1', $execution->resultJson['spf']['analysis']['version'] ?? null);
        $facts = ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson, $execution->spfRawResult);
        $this->assertSame($spfPayload['record'], $facts['spf_record']);
        $this->assertSame($spfPayload['lookups'], $facts['spf_lookups']);
    }

    public function test_blacklist_clean_and_listed_scenarios(): void
    {
        $clean = $this->runPipeline(
            spfRecord: 'v=spf1 -all',
            spfLookups: 1,
            blacklist: FixtureLoader::input('blacklist-clean'),
        );

        $resolver = new \Tests\Support\EmailSecurity\FakeBlacklistDnsResolver();
        $resolver->setDefaultListed(true);
        $this->bindFakeBlacklistDns($resolver);

        $listed = $this->runPipeline(
            spfRecord: 'v=spf1 -all',
            spfLookups: 1,
            blacklist: FixtureLoader::input('blacklist-listed'),
            domainName: 'scenario.test',
        );

        $this->assertTrue($clean->resultJson['blacklist']['is_clean']);
        $this->assertFalse($listed->resultJson['blacklist']['is_clean']);
        $this->assertGreaterThan(0, $listed->resultJson['blacklist']['listed_count']);
    }

    public function test_partial_checker_failure_aborts_scan(): void
    {
        $failing = new class implements SecurityCheckInterface {
            public function key(): string
            {
                return 'spf';
            }

            public function run(CheckContextDTO $context, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns): CheckExecutionResultDTO
            {
                throw new \RuntimeException('Controlled SPF checker failure');
            }
        };

        $this->app->instance(CheckRegistry::class, new CheckRegistry([
            $failing,
            app(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck::class),
        ]));

        $domain = Domain::factory()->create(['domain' => 'fail.test']);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Controlled SPF checker failure');

        app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => false, 'monitoring' => false]),
            microtime(true),
        );
    }

    public function test_report_view_model_matches_golden_snapshot(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $this->mock(ScanTrendService::class, function ($mock): void {
            $mock->shouldReceive('getDomainTrend')->andReturn([
                'labels' => ['Jan', 'Feb'],
                'scores' => [70, 75],
            ]);
        });

        $execution = $this->runPipeline(
            spfRecord: FixtureLoader::input('spf-configured')['record'],
            spfLookups: FixtureLoader::input('spf-configured')['lookups'],
            blacklist: FixtureLoader::input('blacklist-clean'),
            user: $user,
            flattenedSpf: FixtureLoader::input('spf-configured')['flattened'],
            dmarcToken: 'goldenfixturetoken',
        );

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

        $viewModel = app(ScanReportFactoryInterface::class)
            ->build($scan, $domain)
            ->toArray();

        $expected = FixtureLoader::expected('report-view/full-scan');
        $actual = [
            'score' => $viewModel['score'],
            'recommendation_keys' => array_column($viewModel['recommendations'] ?? [], 'key'),
            'status_card_labels' => [
                'blacklist' => $viewModel['statusCards']['blacklist']['label'] ?? null,
                'spf' => $viewModel['statusCards']['spf']['card_label'] ?? null,
                'dmarc' => $viewModel['statusCards']['dmarc']['status'] ?? null,
            ],
        ];

        $this->assertSame($expected['score'], $actual['score']);
        $this->assertSame($expected['recommendation_keys'], $actual['recommendation_keys']);
        $this->assertSame($expected['status_card_labels'], $actual['status_card_labels']);
        $this->assertSame(
            JsonParityNormalizer::normalize($expected['result_json']),
            JsonParityNormalizer::normalize($viewModel['resultData'] ?? [])
        );
    }

    /**
     * @param array<string, mixed> $blacklist
     */
    private function runPipeline(
        ?string $spfRecord,
        int $spfLookups,
        array $blacklist,
        string $domainName = 'scenario.test',
        ?User $user = null,
        ?string $flattenedSpf = null,
        ?string $dmarcToken = null,
    ): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO {
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck::class);
        $this->app->forgetInstance(CheckRegistry::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Mx\MxCheck::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Mx\MxAnalysisService::class);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface::class);

        FixtureLoader::bindDnsCollector(FixtureLoader::input('dns-bundled-full'));
        FixtureLoader::bindDkimResolver($domainName);
        FixtureLoader::bindMtaStsFixtures();
        FixtureLoader::bindTlsRptFixtures();
        FixtureLoader::bindBimiFixtures();
        FixtureLoader::bindMxFixtures(FixtureLoader::input('dns-bundled-full'), $domainName);
        CertificateTestProbeFactory::bindFakeProbes();

        if ($spfRecord !== null) {
            FixtureLoader::bindNativeSpfDns($domainName, $spfRecord);
        } else {
            $dnsPayload = FixtureLoader::input('dns-bundled-full');
            $dnsPayload['records']['SPF'] = ['status' => 'missing'];
            $dnsPayload['root_txt_records'] = [];
            FixtureLoader::bindDnsCollector($dnsPayload);
            $dns = new FakeDnsClient();
            $dns->setTxt($domainName, new DnsResult([], true));
            app()->instance(\App\Services\Dns\DnsClient::class, $dns);
        }

        $user ??= User::factory()->create();
        $domainAttributes = [
            'domain' => $domainName,
            'user_id' => $user->id,
        ];
        if ($dmarcToken !== null) {
            $domainAttributes['dmarc_token'] = $dmarcToken;
        }
        $domain = Domain::factory()->create($domainAttributes);
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
}
