<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Models\Domain;
use App\Models\Scan;

use App\Services\Dns\DnsClient;
use App\Services\Dns\DnsResult;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\FakeDnsClient;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\BindsFakeBlacklistDns;
use Tests\TestCase;

class NativeSpfPipelineTest extends TestCase
{
    use BindsFakeBlacklistDns;
    use RefreshDatabase;

    private ScoreBreakdownService $scoreBreakdownService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
        $this->scoreBreakdownService = new ScoreBreakdownService();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_healthy_native_spf_pipeline_payload(): void
    {
        $execution = $this->runPipeline('native-healthy.test', 'v=spf1 a mx -all');

        $this->assertSame('valid', $execution->resultJson['spf']['protocol_status'] ?? null);
        $this->assertSame('spf-native-v1', $execution->resultJson['spf']['analysis']['version'] ?? null);
        $this->assertSame('hard_fail', $execution->resultJson['spf']['analysis']['terminal_policy'] ?? null);
        $this->assertSame(20, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_missing_native_spf_pipeline(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $dnsPayload['records']['SPF'] = ['status' => 'missing'];
        $dnsPayload['root_txt_records'] = [];
        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(DnsClient::class, new FakeDnsClient());

        $domain = Domain::factory()->create(['domain' => 'native-missing.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $execution = app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => false]),
            microtime(true),
        );

        $this->assertNull($execution->resultJson['spf']['record'] ?? null);
        $this->assertSame('none', $execution->resultJson['spf']['protocol_status'] ?? null);
        $this->assertSame(0, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
        $this->assertTrue(collect($execution->recommendations)->contains(fn ($item) => ($item['key'] ?? '') === 'spf_missing'));
    }

    public function test_exactly_ten_lookups_scores_sixteen(): void
    {
        $dns = new FakeDnsClient();
        $chain = implode(' ', array_map(fn ($i) => "include:inc{$i}.test", range(1, 10)));
        $record = "v=spf1 {$chain} -all";

        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $dnsPayload['records']['SPF'] = ['status' => 'found', 'data' => $record];
        $dnsPayload['root_txt_records'] = [['host' => 'native-ten.test', 'txt' => $record, 'ttl' => 300]];
        FixtureLoader::bindDnsCollector($dnsPayload);

        for ($i = 1; $i <= 10; $i++) {
            $dns->setTxt("inc{$i}.test", new DnsResult(['v=spf1 -all'], true));
        }
        $this->app->instance(DnsClient::class, $dns);

        $domain = Domain::factory()->create(['domain' => 'native-ten.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $execution = app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => false]),
            microtime(true),
        );

        $this->assertSame(10, $execution->resultJson['spf']['lookups']);
        $this->assertSame('valid', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(16, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);

        $card = (new ScanReportStatusMapper())->mapSpf(
            $execution->resultJson['dns']['records']['SPF'] ?? null,
            $execution->resultJson['spf'] ?? null,
        );
        $this->assertSame('warning', $card['state']);
        $this->assertSame('Published', $card['status']);
    }

    public function test_eleven_lookups_scores_zero(): void
    {
        $dns = new FakeDnsClient();
        $chain = implode(' ', array_map(fn ($i) => "include:inc{$i}.test", range(1, 11)));
        $record = "v=spf1 {$chain} -all";

        $execution = $this->runPipeline('native-eleven.test', $record, $dns, function () use ($dns): void {
            for ($i = 1; $i <= 11; $i++) {
                $dns->setTxt("inc{$i}.test", new DnsResult(['v=spf1 -all'], true));
            }
        });

        $this->assertSame('permerror', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(0, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_multiple_spf_records_scores_zero(): void
    {
        $recordA = 'v=spf1 -all';
        $recordB = 'v=spf1 include:other.test -all';
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $dnsPayload['records']['SPF'] = ['status' => 'found', 'data' => $recordA];
        $dnsPayload['root_txt_records'] = [
            ['host' => 'native-multi.test', 'txt' => $recordA, 'ttl' => 300],
            ['host' => 'native-multi.test', 'txt' => $recordB, 'ttl' => 300],
        ];
        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(DnsClient::class, new FakeDnsClient());

        $domain = Domain::factory()->create(['domain' => 'native-multi.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $execution = app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => false]),
            microtime(true),
        );

        $this->assertSame('permerror', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(0, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_invalid_syntax_scores_zero(): void
    {
        $execution = $this->runPipeline('native-invalid.test', 'v=spf1 ?? -all');

        $this->assertSame('permerror', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(0, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_plus_all_scores_zero(): void
    {
        $execution = $this->runPipeline('native-plusall.test', 'v=spf1 +all');

        $this->assertSame('permerror', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(0, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_dns_timeout_scores_eight(): void
    {
        $dns = new FakeDnsClient();
        $dns->setTxt('timeout.test', new DnsResult([], false, 'DNS timeout'));

        $execution = $this->runPipeline('native-timeout.test', 'v=spf1 exists:timeout.test -all', $dns);

        $this->assertSame('temperror', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(8, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_unsupported_macro_scores_eight(): void
    {
        $execution = $this->runPipeline('native-macro.test', 'v=spf1 exp=%{i} -all');

        $this->assertSame('partially_evaluated', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(8, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_soft_fail_scores_fifteen(): void
    {
        $execution = $this->runPipeline('native-softfail.test', 'v=spf1 ~all');

        $this->assertSame('valid', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(15, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_deprecated_ptr_scores_eighteen(): void
    {
        $execution = $this->runPipeline('native-ptr.test', 'v=spf1 ptr -all');

        $this->assertSame('valid', $execution->resultJson['spf']['protocol_status']);
        $this->assertSame(18, $this->spfEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_blacklist_with_native_spf_preserves_score_invariant(): void
    {
        $blacklistPayload = FixtureLoader::input('blacklist-clean');
        $this->bindFakeBlacklistDns();

        $execution = $this->runPipeline('native-blacklist.test', 'v=spf1 a mx -all', null, null, true);

        $this->assertArrayHasKey('blacklist', $execution->resultJson);
        $this->assertScoreInvariant($execution);
    }

    public function test_bundled_dns_with_native_spf_preserves_score_invariant(): void
    {
        $execution = $this->runPipeline('native-bundled.test', 'v=spf1 a mx -all');

        $this->assertArrayHasKey('dns', $execution->resultJson);
        $this->assertArrayHasKey('score_breakdown', $execution->resultJson['dns']);
        $this->assertSame($execution->score, $execution->resultJson['dns']['score']);
        $this->assertScoreInvariant($execution);
    }

    /**
     * @param callable(): void|null $configureDns
     */
    private function runPipeline(
        string $domainName,
        string $record,
        ?FakeDnsClient $dns = null,
        ?callable $configureDns = null,
        bool $withBlacklist = false,
    ): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO {
        $dns ??= new FakeDnsClient();
        $configureDns && $configureDns();

        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $dnsPayload['records']['SPF'] = ['status' => 'found', 'data' => $record];
        $dnsPayload['root_txt_records'] = [['host' => $domainName, 'txt' => $record, 'ttl' => 300]];
        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(DnsClient::class, $dns);

        $domain = Domain::factory()->create(['domain' => $domainName]);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray([
                'dns' => true,
                'spf' => true,
                'blacklist' => $withBlacklist,
            ]),
            microtime(true),
        );
    }

    /**
     * @param \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution
     */
    private function spfEarned($execution): int
    {
        $row = $this->scoreBreakdownService->findRow(
            $execution->resultJson['dns']['score_breakdown'] ?? [],
            'spf'
        );

        return (int) ($row['earned'] ?? -1);
    }

    /**
     * @param \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution
     */
    private function assertScoreInvariant($execution): void
    {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        $sum = $this->scoreBreakdownService->totalEarned($breakdown);

        $this->assertSame($execution->score, $sum, 'scans.score must equal sum(score_breakdown[*].earned)');
        $this->assertSame($execution->score, $execution->resultJson['dns']['score'] ?? null);
    }
}
