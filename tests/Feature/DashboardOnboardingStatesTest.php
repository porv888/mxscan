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
        $response->assertSee('Latest Email Security Score', false);
        $response->assertSee('Add SPF Record', false);
        $response->assertSee('View full report', false);
    }
}
