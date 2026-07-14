<?php

namespace Tests\Feature;

use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Support\DomainNormalizer;
use Illuminate\Support\Facades\Bus;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class DomainOnboardingTest extends TestCase
{
    use UsesSqliteDmarcSchema;
    use CreatesPlanUsers;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpSqliteMonitoringExtras();
        $this->setUpPlanTables();
        Bus::fake();
    }

    public function test_domain_only_form_creates_defaults_and_dispatches_scan(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->post(route('dashboard.domains.store'), [
            'domain' => 'https://www.Example.com/path?x=1',
        ]);

        $domain = Domain::where('user_id', $user->id)->first();
        $this->assertNotNull($domain);
        $this->assertSame('example.com', $domain->domain);
        $this->assertSame('prod', $domain->environment);

        $schedule = $domain->schedules()->first() ?? \App\Models\Schedule::where('domain_id', $domain->id)->first();
        $this->assertNull($schedule);

        $scan = Scan::where('domain_id', $domain->id)->first();
        $this->assertNotNull($scan);
        $this->assertSame('queued', $scan->status);
        $this->assertSame($user->id, $scan->user_id);

        $response->assertRedirect(route('reports.show', $scan));

        Bus::assertDispatched(RunFullScan::class, function (RunFullScan $job) use ($domain, $scan) {
            return $job->domainId === $domain->id
                && ($job->options['scan_id'] ?? null) === $scan->id;
        });
    }

    public function test_advanced_options_are_respected_for_paid_users(): void
    {
        $user = $this->createPremiumUser();

        $this->actingAs($user)->post(route('dashboard.domains.store'), [
            'domain' => 'advanced-test.example.com',
            'environment' => 'dev',
            'services' => ['dns', 'delivery'],
            'schedule' => 'daily@10:00',
        ]);

        $domain = Domain::where('domain', 'advanced-test.example.com')->first();
        $this->assertSame('dev', $domain->environment);
        $schedule = \App\Models\Schedule::where('domain_id', $domain->id)->first();
        $this->assertSame('active', $schedule->status);
        $this->assertSame('daily', $schedule->frequency);
        $this->assertContains('delivery', $schedule->settings['services']);
    }

    public function test_malformed_domain_rejected(): void
    {
        $user = User::factory()->create();
        $response = $this->actingAs($user)->from(route('dashboard.domains.create'))
            ->post(route('dashboard.domains.store'), [
                'domain' => 'not a domain',
            ]);

        $response->assertRedirect(route('dashboard.domains.create'));
        $response->assertSessionHasErrors('domain');
        $this->assertSame(0, Domain::count());
        Bus::assertNotDispatched(RunFullScan::class);
    }

    public function test_duplicate_normalized_domain_rejected(): void
    {
        $user = User::factory()->create();
        Domain::create([
            'user_id' => $user->id,
            'domain' => 'dupe.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokendupecreate00000000001',
        ]);

        $response = $this->actingAs($user)->from(route('dashboard.domains.create'))
            ->post(route('dashboard.domains.store'), [
                'domain' => 'https://www.dupe.example.com/x',
            ]);

        $response->assertSessionHasErrors('domain');
        $this->assertSame(1, Domain::where('user_id', $user->id)->count());
    }

    public function test_normalizer_matches_store_expectations(): void
    {
        $this->assertSame('example.com', DomainNormalizer::normalize('https://example.com/path'));
    }
}
