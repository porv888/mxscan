<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Support\Str;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class ScanPendingReportTest extends TestCase
{
    use UsesSqliteDmarcSchema;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpSqliteMonitoringExtras();
    }

    protected function makeScan(User $user, string $status, int $progress = 0): Scan
    {
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'scan-' . Str::random(6) . '.test',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => Str::random(24),
        ]);

        return Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => $status,
            'progress_pct' => $progress,
            'finished_at' => $status === 'finished' ? now() : null,
            'score' => $status === 'finished' ? 80 : null,
            'result_json' => match ($status) {
                'finished' => [
                    'dns' => [
                        'score' => 80,
                        'records' => [
                            'MX' => ['status' => 'found', 'data' => [['target' => 'mail.example.com']]],
                            'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                            'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1', 'record' => 'v=DKIM1; p=abc']]],
                            'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject; adkim=r; aspf=r'],
                            'TLS-RPT' => ['status' => 'found', 'data' => 'v=TLSRPTv1'],
                            'MTA-STS' => ['status' => 'found', 'data' => 'v=STSv1', 'policy' => 'x'],
                        ],
                    ],
                    'spf' => ['lookups' => 1, 'valid' => true],
                    'blacklist' => ['total_checks' => 3, 'listed_count' => 0],
                ],
                'failed' => ['user_error' => 'The scan could not be completed. Please try again.'],
                default => null,
            },
        ]);
    }

    public function test_queued_state_shows_pending_ui(): void
    {
        $user = User::factory()->create();
        $scan = $this->makeScan($user, 'queued');
        $response = $this->actingAs($user)->get(route('reports.show', $scan));
        $response->assertOk();
        $response->assertSee('Scanning ' . $scan->domain->domain, false);
        $response->assertSee('Queued', false);
        $response->assertDontSee('All Clear!', false);
    }

    public function test_running_state_shows_scanning_stage(): void
    {
        $user = User::factory()->create();
        $scan = $this->makeScan($user, 'running', 40);
        $response = $this->actingAs($user)->get(route('reports.show', $scan));
        $response->assertOk();
        $response->assertSee('Scanning', false);
        $status = $this->actingAs($user)->getJson(route('scans.status', $scan));
        $status->assertOk()->assertJsonPath('stage', 'scanning');
    }

    public function test_failed_state_shows_retry(): void
    {
        $user = User::factory()->create();
        $scan = $this->makeScan($user, 'failed');
        $response = $this->actingAs($user)->get(route('reports.show', $scan));
        $response->assertOk();
        $response->assertSee('Retry scan', false);
        $response->assertSee('The scan could not be completed', false);
    }

    public function test_finished_state_renders_report(): void
    {
        $user = User::factory()->create();
        $scan = $this->makeScan($user, 'finished');
        $response = $this->actingAs($user)->get(route('reports.show', $scan));
        $response->assertOk();
        $response->assertSee('Email Security Score', false);
        $response->assertDontSee('First scan in progress', false);
    }

    public function test_cannot_access_another_users_scan(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $scan = $this->makeScan($owner, 'queued');
        $this->actingAs($other)->get(route('reports.show', $scan))->assertForbidden();
        $this->actingAs($other)->getJson(route('scans.status', $scan))->assertForbidden();
    }
}
