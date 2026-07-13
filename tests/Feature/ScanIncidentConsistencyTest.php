<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\Incident;
use App\Models\Scan;
use App\Models\ScanSnapshot;
use App\Models\User;
use App\Services\MonitoringService;
use App\Services\ScanReport\ScanFinalizer;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Str;
use Mockery;
use ReflectionMethod;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class ScanIncidentConsistencyTest extends TestCase
{
    use UsesSqliteDmarcSchema;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpSqliteMonitoringExtras();
        Bus::fake();
    }

    protected function makeDomain(): Domain
    {
        $user = User::factory()->create();

        return Domain::create([
            'user_id' => $user->id,
            'domain' => 'inc-' . Str::random(8) . '.test',
            'dmarc_token' => Str::random(24),
        ]);
    }

    protected function invokeCreateIncident(
        MonitoringService $service,
        Domain $domain,
        string $kind,
        string $severity,
        string $message,
        array $context = []
    ): void {
        $method = new ReflectionMethod(MonitoringService::class, 'createIncident');
        $method->setAccessible(true);
        $method->invoke($service, $domain, $kind, $severity, $message, $context);
    }

    public function test_create_incident_dedupes_open_incident_same_domain_type_field(): void
    {
        $domain = $this->makeDomain();
        $service = app(MonitoringService::class);

        $this->invokeCreateIncident(
            $service,
            $domain,
            'record_missing',
            'warning',
            'SPF record became invalid or missing.',
            ['field' => 'spf_ok']
        );

        $first = Incident::query()->where('domain_id', $domain->id)->first();
        $this->assertNotNull($first);
        $firstOccurred = $first->occurred_at;

        $this->travel(2)->minutes();

        $this->invokeCreateIncident(
            $service,
            $domain,
            'record_missing',
            'incident',
            'SPF record became invalid or missing.',
            ['field' => 'spf_ok']
        );

        $this->assertSame(1, Incident::query()->where('domain_id', $domain->id)->whereNull('resolved_at')->count());
        $updated = Incident::query()->where('domain_id', $domain->id)->first();
        $this->assertSame('incident', $updated->severity);
        $this->assertTrue($updated->occurred_at->gt($firstOccurred));
    }

    public function test_scan_finalizer_noop_when_raise_incidents_false(): void
    {
        $domain = $this->makeDomain();
        $scan = Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'type' => 'full',
            'status' => 'finished',
            'finished_at' => now(),
        ]);

        $monitoring = Mockery::mock(MonitoringService::class);
        $monitoring->shouldNotReceive('persistSnapshot');
        $monitoring->shouldNotReceive('computeDeltaAndIncidents');
        $this->app->instance(MonitoringService::class, $monitoring);

        app(ScanFinalizer::class)->finalizeMonitoredScan(
            $domain,
            $scan,
            ['dns' => ['records' => [], 'score' => 50]],
            'full',
            false
        );

        $this->assertSame(0, ScanSnapshot::query()->where('domain_id', $domain->id)->count());
    }

    public function test_scan_finalizer_persists_snapshot_when_raise_incidents_true(): void
    {
        $domain = $this->makeDomain();
        $scan = Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'type' => 'full',
            'status' => 'finished',
            'finished_at' => now(),
        ]);

        $results = [
            'dns' => [
                'score' => 85,
                'records' => [
                    'MX' => ['status' => 'found'],
                    'SPF' => ['status' => 'found'],
                    'DMARC' => ['status' => 'found'],
                    'TLS-RPT' => ['status' => 'missing'],
                    'MTA-STS' => ['status' => 'missing'],
                ],
            ],
            'spf' => ['lookups' => 2],
            'blacklist' => ['total_checks' => 1, 'listed_count' => 0],
        ];

        app(ScanFinalizer::class)->finalizeMonitoredScan(
            $domain,
            $scan,
            $results,
            'full',
            true
        );

        $this->assertSame(1, ScanSnapshot::query()->where('domain_id', $domain->id)->count());
        $snapshot = ScanSnapshot::query()->where('domain_id', $domain->id)->first();
        $this->assertTrue($snapshot->mx_ok);
        $this->assertTrue($snapshot->spf_ok);
        $this->assertSame(85, $snapshot->score);
    }
}
