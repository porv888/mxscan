<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Support\Str;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class DashboardOnboardingStatesTest extends TestCase
{
    use UsesSqliteDmarcSchema;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpSqliteMonitoringExtras();
    }

    public function test_no_domains_shows_first_domain_onboarding_only(): void
    {
        $user = User::factory()->create();
        $response = $this->actingAs($user)->get(route('dashboard'));
        $response->assertOk();
        $response->assertSee('Scan your first domain', false);
        $response->assertDontSee('Domains at Risk', false);
        $response->assertDontSee('Email Security Score (30 days)', false);
    }

    public function test_domain_with_no_scan_shows_ready_to_scan(): void
    {
        $user = User::factory()->create();
        Domain::create([
            'user_id' => $user->id,
            'domain' => 'ready-' . Str::random(6) . '.test',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => Str::random(24),
        ]);

        $response = $this->actingAs($user)->get(route('dashboard'));
        $response->assertOk();
        $response->assertSee('Your domain is ready to scan', false);
        $response->assertDontSee('Domains at Risk', false);
    }

    public function test_pending_first_scan_shows_progress_not_kpis(): void
    {
        $user = User::factory()->create();
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'pending-' . Str::random(6) . '.test',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => Str::random(24),
        ]);
        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => 'running',
            'progress_pct' => 33,
        ]);

        $response = $this->actingAs($user)->get(route('dashboard'));
        $response->assertOk();
        $response->assertSee('First scan in progress', false);
        $response->assertSee('View scan progress', false);
        $response->assertDontSee('Domains at Risk', false);
    }

    public function test_completed_first_scan_shows_score_and_findings(): void
    {
        $user = User::factory()->create();
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'done-' . Str::random(6) . '.test',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => Str::random(24),
            'score_last' => 55,
        ]);
        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => 'finished',
            'score' => 55,
            'finished_at' => now(),
            'result_json' => [
                'dns' => [
                    'score' => 55,
                    'records' => [
                        'MX' => ['status' => 'found'],
                        'SPF' => ['status' => 'missing'],
                        'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
                        'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject; adkim=r; aspf=r'],
                        'TLS-RPT' => ['status' => 'missing'],
                        'MTA-STS' => ['status' => 'missing'],
                    ],
                ],
                'blacklist' => ['total_checks' => 2, 'listed_count' => 0],
                'spf' => ['lookups' => 0, 'valid' => true],
            ],
        ]);

        $response = $this->actingAs($user)->get(route('dashboard'));
        $response->assertOk();
        $response->assertSee('Latest security score', false);
        $response->assertSee('SPF is missing', false);
        $response->assertSee('Fix SPF', false);
        $response->assertSee('View full report', false);
    }

    public function test_latest_completed_scan_is_the_authoritative_dashboard_source(): void
    {
        $user = User::factory()->create();
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'mxscan.me',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => Str::random(24),
            'score_last' => 0,
        ]);
        $resultJson = json_decode(
            file_get_contents(base_path('tests/Fixtures/EmailSecurity/mxscan-me-scan-result.json')),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => 'finished',
            'score' => 42,
            'finished_at' => now()->subDay(),
            'result_json' => $resultJson,
        ]);
        $latestScan = Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => 'finished',
            'score' => 64,
            'finished_at' => now(),
            'result_json' => $resultJson,
        ]);

        $response = $this->actingAs($user)->get(route('dashboard'));
        $response->assertOk();
        $response->assertSee('64 <span>/ 100</span>', false);
        $response->assertDontSee('score of 0%', false);
        $response->assertDontSee('Improve security score', false);
        $response->assertSee('Fix SPF', false);
        $response->assertSee('Relink MXScan reporting', false);
        $response->assertSee('Resolve external DMARC authorization', false);
        $response->assertSee('Review authorization', false);
        $response->assertSee('Active security incidents', false);
        $response->assertSee('Configuration findings are listed separately.', false);
        $response->assertSee('2 scans available', false);
        $response->assertSee('More history will appear as scheduled scans run.', false);
        $response->assertSee('dashboard-metric-grid', false);
        $response->assertSee('aria-label="Mobile navigation"', false);
        $response->assertDontSee('View Report', false);
        $response->assertDontSee('Configured', false);

        $hero = $response->viewData('dashboardHero');
        $history = $response->viewData('dashboardScoreHistory');
        $recommendations = $response->viewData('dashboardRecommendations');

        $this->assertSame((string) $latestScan->id, $hero['scan_id']);
        $this->assertSame($domain->id, $hero['domain_id']);
        $this->assertSame(64, $hero['score']);
        $this->assertSame(64, $history['scores'][array_key_last($history['scores'])]);
        $this->assertSame((string) $latestScan->id, $history['scan_ids'][array_key_last($history['scan_ids'])]);
        $this->assertSame('spf_missing', $recommendations->first()['key']);
        $this->assertSame('Fix SPF', $recommendations->first()['action_label']);
        $this->assertLessThan(
            $recommendations->search(fn (array $item) => $item['key'] === 'dmarc_rua_unauthorized'),
            $recommendations->search(fn (array $item) => $item['key'] === 'spf_missing'),
        );
    }
}
