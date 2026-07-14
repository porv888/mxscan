<?php

namespace Tests\Feature;

use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\User;
use Illuminate\Support\Facades\Bus;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class FreePlanDomainLimitTest extends TestCase
{
    use UsesSqliteDmarcSchema;
    use CreatesPlanUsers;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpSqliteMonitoringExtras();
        $this->setUpPlanTables();
        config(['plans.limits.freemium' => 1]);
        Bus::fake();
    }

    public function test_domains_index_shows_one_of_one_domain_used(): void
    {
        $user = User::factory()->create();
        Domain::create([
            'user_id' => $user->id,
            'domain' => 'used.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000010',
        ]);

        $response = $this->actingAs($user)->get(route('domains'));

        $response->assertOk();
        $response->assertSee('1 of 1 domain used', false);
    }

    public function test_add_domain_button_becomes_upgrade_cta_at_limit(): void
    {
        $user = User::factory()->create();
        Domain::create([
            'user_id' => $user->id,
            'domain' => 'limit.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000011',
        ]);

        $response = $this->actingAs($user)->get(route('domains'));

        $response->assertOk();
        $response->assertSee('Upgrade to add more domains', false);
        $response->assertDontSee('Add Domain', false);
    }

    public function test_store_rejects_second_domain_for_free_user(): void
    {
        $user = User::factory()->create();
        Domain::create([
            'user_id' => $user->id,
            'domain' => 'first.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000012',
        ]);

        $response = $this->actingAs($user)->from(route('dashboard.domains.create'))
            ->post(route('dashboard.domains.store'), [
                'domain' => 'second.example.com',
            ]);

        $response->assertSessionHasErrors('domain');
        $this->assertSame(1, Domain::where('user_id', $user->id)->count());
        Bus::assertNotDispatched(RunFullScan::class);
    }

    public function test_tools_route_blocked_for_free_user(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get(route('tools.index'));

        $response->assertRedirect(route('pricing'));
    }

    public function test_automations_route_blocked_for_free_user(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get(route('automations.index'));

        $response->assertRedirect(route('pricing'));
    }

    public function test_dmarc_route_blocked_for_free_user(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get(route('dmarc.index'));

        $response->assertRedirect(route('pricing'));
    }

    public function test_locked_domain_blocks_scan(): void
    {
        $user = User::factory()->create();
        $active = Domain::create([
            'user_id' => $user->id,
            'domain' => 'active.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000013',
            'created_at' => now()->subDay(),
        ]);
        $locked = Domain::create([
            'user_id' => $user->id,
            'domain' => 'locked.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000014',
            'created_at' => now(),
        ]);

        $response = $this->actingAs($user)->post(route('domains.scan.now', $locked), [
            'mode' => 'full',
        ]);

        $response->assertRedirect();
        Bus::assertNotDispatched(RunFullScan::class);
    }
}
