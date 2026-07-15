<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\Contracts\ScanPersisterInterface;
use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Recommendations\ScanRecommendationService;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\Dns\DnsClient;
use App\Services\Dns\DnsResult;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\FakeDnsClient;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class NativeSpfRolloutMatrixTest extends TestCase
{
    use RefreshDatabase;

    private ScoreBreakdownService $breakdown;

    protected function setUp(): void
    {
        parent::setUp();
        $this->resetNativeSpfContainer();
        $this->breakdown = new ScoreBreakdownService();
    }

    private function resetNativeSpfContainer(): void
    {
        foreach ([
            \App\Domain\EmailSecurity\Checks\CheckRegistry::class,
            \App\Domain\EmailSecurity\Checks\SPF\SpfCheck::class,
            \App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluator::class,
            \App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver::class,
            \App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery::class,
        ] as $class) {
            $this->app->forgetInstance($class);
        }
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_controlled_scan_matrix_and_persisted_reload(): void
    {
        $matrix = [
            'no_spf' => ['record' => null, 'earned' => 0, 'terminal' => SpfTerminalPolicy::IMPLICIT_NEUTRAL],
            'ip4_all' => ['record' => 'v=spf1 ip4:203.0.113.10 -all', 'earned' => 20, 'terminal' => SpfTerminalPolicy::HARD_FAIL],
            'google_chain' => ['record' => 'v=spf1 include:_spf.google.com -all', 'earned' => 20, 'terminal' => SpfTerminalPolicy::HARD_FAIL, 'txt' => ['_spf.google.com' => 'v=spf1 -all']],
            'microsoft_chain' => ['record' => 'v=spf1 include:spf.protection.outlook.com -all', 'earned' => 20, 'terminal' => SpfTerminalPolicy::HARD_FAIL, 'txt' => ['spf.protection.outlook.com' => 'v=spf1 -all']],
            'multiple_records' => ['records' => ['v=spf1 -all', 'v=spf1 include:x.test -all'], 'earned' => 0],
            'invalid_syntax' => ['record' => 'v=spf1 ?? -all', 'earned' => 0],
            'ten_lookups' => ['record' => 'ten', 'earned' => 16],
            'eleven_lookups' => ['record' => 'eleven', 'earned' => 0],
            'redirect_valid' => ['record' => 'v=spf1 redirect=good.test', 'earned' => 20, 'txt' => ['good.test' => 'v=spf1 -all']],
            'redirect_empty' => ['record' => 'v=spf1 redirect=empty.test', 'earned' => 0, 'txt' => ['empty.test' => '']],
            'deprecated_ptr' => ['record' => 'v=spf1 ptr -all', 'earned' => 18],
            'unsupported_macro' => ['record' => 'v=spf1 exp=%{i} -all', 'earned' => 8],
            'spf_only' => ['record' => 'v=spf1 -all', 'earned' => 20, 'dns' => false],
        ];

        foreach ($matrix as $name => $scenario) {
            $execution = $this->runScenario($name, $scenario);
            $spf = $execution->resultJson['spf'];
            $analysis = $spf['analysis'] ?? [];
            $spfRow = $this->breakdown->findRow($execution->resultJson['dns']['score_breakdown'] ?? [], 'spf');

            $this->assertSame($scenario['earned'], $spfRow['earned'] ?? null, "{$name} earned");
            $this->assertSame($execution->score, $this->breakdown->totalEarned($execution->resultJson['dns']['score_breakdown'] ?? []), "{$name} invariant");
            $this->assertSame('spf-native-v1', $analysis['version'] ?? null, "{$name} version");

            if (isset($scenario['terminal'])) {
                $this->assertSame($scenario['terminal'], $analysis['terminal_policy'] ?? null, "{$name} terminal");
            }

            $domain = Domain::factory()->create(['domain' => "persist-{$name}.test"]);
            $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id, 'status' => 'running']);
            app(ScanPersisterInterface::class)->saveFinished(
                $scan,
                $domain,
                $execution,
                ScanOptionsDTO::fromArray(['dns' => $scenario['dns'] ?? true, 'spf' => true, 'blacklist' => false]),
                ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson, $execution->spfRawResult),
            );

            $reloaded = Scan::query()->findOrFail($scan->id);
            $this->assertSame($execution->score, $reloaded->score, "{$name} persisted score");
            $this->assertSame('spf-native-v1', $reloaded->result_json['spf']['analysis']['version'] ?? null, "{$name} persisted analysis");

            $user = User::factory()->create();
            $this->actingAs($user);
            $report = app(ScanReportFactoryInterface::class)->build($reloaded, $domain);
            $this->assertIsArray($report->toArray()['statusCards']['spf'] ?? null, "{$name} report render");
        }
    }

    public function test_native_mode_does_not_invoke_legacy_spf_resolver(): void
    {
        $resolver = Mockery::mock(SpfResolver::class);
        $resolver->shouldReceive('resolve')->never();
        $this->app->instance(SpfResolver::class, $resolver);

        $dns = new FakeDnsClient();
        $dns->setTxt('no-legacy.test', new DnsResult(['v=spf1 -all'], true));
        $this->app->instance(DnsClient::class, $dns);

        $domain = Domain::factory()->create(['domain' => 'no-legacy.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => false]),
            microtime(true),
        );

        $this->addToAssertionCount(1);
    }

    public function test_user_facing_language_avoids_unauthorized_sender_wording(): void
    {
        $forbidden = [
            'SPF passes',
            'Sender is authorized',
            'Authorized senders were verified',
            'Outgoing email is authenticated',
        ];

        $paths = [
            app_path('View/Presenters/ScanReportPresenter.php'),
            app_path('Domain/EmailSecurity/Reporting/ScanReportStatusMapper.php'),
            app_path('Domain/EmailSecurity/Checks/SPF/Recommendations/SpfRecommendationEvaluator.php'),
        ];

        foreach ($paths as $path) {
            $contents = (string) file_get_contents($path);
            foreach ($forbidden as $phrase) {
                $this->assertStringNotContainsString($phrase, $contents, "{$path} contains forbidden phrase");
            }
        }
    }

    /**
     * @param array<string, mixed> $scenario
     */
    private function runScenario(string $name, array $scenario): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO
    {
        $dns = new FakeDnsClient();
        $domainName = "matrix-{$name}.test";
        $rootSpfRecord = null;

        if (isset($scenario['records'])) {
            $txt = [];
            foreach ($scenario['records'] as $record) {
                $txt[] = $record;
            }
            $rootSpfRecord = $scenario['records'][0];
            $dns->setTxt($domainName, new DnsResult($txt, true));
        } elseif (($scenario['record'] ?? null) === 'ten') {
            $chain = implode(' ', array_map(fn ($i) => "include:inc{$i}.test", range(1, 10)));
            $rootSpfRecord = "v=spf1 {$chain} -all";
            $dns->setTxt($domainName, new DnsResult([$rootSpfRecord], true));
            for ($i = 1; $i <= 10; $i++) {
                $dns->setTxt("inc{$i}.test", new DnsResult(['v=spf1 -all'], true));
            }
        } elseif (($scenario['record'] ?? null) === 'eleven') {
            $chain = implode(' ', array_map(fn ($i) => "include:inc{$i}.test", range(1, 11)));
            $rootSpfRecord = "v=spf1 {$chain} -all";
            $dns->setTxt($domainName, new DnsResult([$rootSpfRecord], true));
            for ($i = 1; $i <= 11; $i++) {
                $dns->setTxt("inc{$i}.test", new DnsResult(['v=spf1 -all'], true));
            }
        } elseif (($scenario['record'] ?? null) !== null) {
            $rootSpfRecord = $scenario['record'];
            $dns->setTxt($domainName, new DnsResult([$rootSpfRecord], true));
        } else {
            $dns->setTxt($domainName, new DnsResult([], true));
        }

        foreach ($scenario['txt'] ?? [] as $host => $value) {
            $dns->setTxt($host, new DnsResult($value === '' ? [] : [$value], true));
        }

        $this->app->instance(DnsClient::class, $dns);
        $this->resetNativeSpfContainer();

        if ($scenario['dns'] ?? true) {
            $payload = FixtureLoader::input('dns-bundled-full');
            if (isset($scenario['records'])) {
                $payload['records']['SPF'] = ['status' => 'found', 'data' => $scenario['records'][0]];
                $payload['root_txt_records'] = array_map(
                    fn (string $txt) => ['host' => $domainName, 'txt' => $txt, 'ttl' => 3600],
                    $scenario['records'],
                );
            } elseif ($rootSpfRecord !== null) {
                $payload['records']['SPF'] = ['status' => 'found', 'data' => $rootSpfRecord];
            } elseif (array_key_exists('record', $scenario) && $scenario['record'] === null) {
                $payload['records']['SPF'] = ['status' => 'missing'];
            }
            FixtureLoader::bindDnsCollector($payload);
        }

        $domain = Domain::factory()->create(['domain' => $domainName]);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray([
                'dns' => $scenario['dns'] ?? true,
                'spf' => true,
                'blacklist' => false,
            ]),
            microtime(true),
        );
    }
}
