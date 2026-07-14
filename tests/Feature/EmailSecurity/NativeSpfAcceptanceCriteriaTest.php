<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\SPF\Recommendations\SpfRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Contracts\ScanPersisterInterface;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Domain\EmailSecurity\Scoring\ScoreInvariantGuard;
use App\Domain\EmailSecurity\Scoring\ScoreInvariantViolationException;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\Dns\DnsClient;
use App\Services\Dns\DnsResult;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\EmailSecurity\FakeDnsClient;
use Tests\TestCase;

class NativeSpfAcceptanceCriteriaTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['email-security.spf_engine' => 'native']);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
    }

    /**
     * @return array<string, array{0: string, 1: int}>
     */
    public static function spfOnlyScenarioProvider(): array
    {
        return [
            'valid_all' => ['v=spf1 ip4:203.0.113.10 -all', 20],
            'soft_fail' => ['v=spf1 ~all', 15],
            'ten_lookups' => ['ten', 16],
            'invalid_syntax' => ['v=spf1 ?? -all', 0],
            'temperror' => ['timeout', 8],
            'missing' => ['missing', 0],
        ];
    }

    /**
     * @dataProvider spfOnlyScenarioProvider
     */
    public function test_spf_only_native_scoring(string $scenario, int $expectedEarned): void
    {
        $dns = new FakeDnsClient();
        $record = match ($scenario) {
            'ten' => 'v=spf1 ' . implode(' ', array_map(fn ($i) => "include:inc{$i}.test", range(1, 10))) . ' -all',
            'timeout' => 'v=spf1 exists:timeout.test -all',
            'missing' => null,
            default => $scenario,
        };

        if ($scenario === 'ten') {
            for ($i = 1; $i <= 10; $i++) {
                $dns->setTxt("inc{$i}.test", new DnsResult(['v=spf1 -all'], true));
            }
        }
        if ($scenario === 'timeout') {
            $dns->setTxt('timeout.test', new DnsResult([], false, 'DNS timeout'));
        }

        if ($record !== null) {
            $dns->setTxt('spf-only.test', new DnsResult([$record], true));
        } else {
            $dns->setTxt('spf-only.test', new DnsResult([], true));
        }

        $this->app->instance(DnsClient::class, $dns);

        $domain = Domain::factory()->create(['domain' => 'spf-only.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $execution = app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => false]),
            microtime(true),
        );

        $spfRow = collect($execution->resultJson['dns']['score_breakdown'] ?? [])->firstWhere('key', 'spf');
        $this->assertSame($expectedEarned, $spfRow['earned'] ?? null, "Scenario {$scenario}");
        $this->assertSame($execution->score, (new ScoreBreakdownService())->totalEarned($execution->resultJson['dns']['score_breakdown'] ?? []));
        $this->assertArrayHasKey('analysis', $execution->resultJson['spf'] ?? []);
    }

    public function test_redirect_none_permerror_persists_analysis_and_scores_zero(): void
    {
        $dns = new FakeDnsClient();
        $dns->setTxt('redirect-none.test', new DnsResult(['v=spf1 redirect=empty.test'], true));
        $dns->setTxt('empty.test', new DnsResult([], true));
        $this->app->instance(DnsClient::class, $dns);

        $domain = Domain::factory()->create(['domain' => 'redirect-none.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $execution = app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => false]),
            microtime(true),
        );

        $analysis = $execution->resultJson['spf']['analysis'];
        $this->assertSame(SpfProtocolStatus::PERMERROR, $analysis['protocol_status']);
        $this->assertSame('fail', $analysis['state']);
        $this->assertSame(0, collect($execution->resultJson['dns']['score_breakdown'])->firstWhere('key', 'spf')['earned'] ?? null);
        $this->assertTrue(
            collect($analysis['errors'])->contains(fn ($e) => ($e['code'] ?? '') === 'REDIRECT_NONE_PERMERROR')
        );

        $mapper = new ScanReportStatusMapper();
        $card = $mapper->mapSpf(
            $execution->resultJson['dns']['records']['SPF'] ?? null,
            $execution->resultJson['spf'],
        );
        $items = (new SpfRecommendationEvaluator())->evaluate(
            $execution->resultJson['dns']['records']['SPF'] ?? null,
            $card,
            $execution->resultJson['spf'],
        );
        $this->assertTrue(collect($items)->contains(fn ($item) => ($item['semantic_key'] ?? '') === 'fix_invalid_spf'));
    }

    public function test_persistence_aborts_on_score_invariant_violation(): void
    {
        $domain = Domain::factory()->create(['domain' => 'persist.test']);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
            'score' => null,
            'result_json' => null,
        ]);
        $originalScore = $scan->fresh()->score;

        $execution = new \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO(
            resultJson: [
                'dns' => [
                    'score' => 80,
                    'score_breakdown' => [
                        ['key' => 'spf', 'earned' => 20, 'possible' => 20],
                    ],
                ],
            ],
            recommendations: [],
            score: 80,
            durationMs: 10,
            scanType: 'spf',
            spfRawResult: null,
        );

        $this->expectException(ScoreInvariantViolationException::class);

        try {
            app(ScanPersisterInterface::class)->saveFinished(
                $scan,
                $domain,
                $execution,
                ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => false]),
                [],
            );
        } finally {
            $scan->refresh();
            $this->assertSame('running', $scan->status);
            $this->assertSame($originalScore, $scan->score);
            $this->assertNotSame(80, $scan->score);
        }
    }

    public function test_score_invariant_guard_rejects_mismatched_totals_directly(): void
    {
        $this->expectException(ScoreInvariantViolationException::class);
        (new ScoreInvariantGuard(new ScoreBreakdownService()))->assertConsistent(99, [
            ['key' => 'spf', 'earned' => 20, 'possible' => 20],
        ]);
    }
}
