<?php

namespace Tests\Feature;

use App\Models\Domain;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Concerns\CreatesPlanUsers;
use Tests\TestCase;

class ScanNowRouteTest extends TestCase
{
    use CreatesPlanUsers;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpPlanTables();
    }

    public function test_get_scan_now_shows_confirmation_form(): void
    {
        $user = $this->createPremiumUser();
        $domain = Domain::factory()->create(['user_id' => $user->id, 'domain' => 'mxscan.me']);

        $response = $this->actingAs($user)->get(route('domains.scan.now.show', $domain));

        $response->assertOk();
        $response->assertSee('Run scan');
        $response->assertSee('mxscan.me');
        $response->assertSee('name="_token"', false);
        $response->assertSee('value="full"', false);
    }

    public function test_get_scan_now_replaces_post_only_405_for_direct_visits(): void
    {
        $user = $this->createPremiumUser();
        $domain = Domain::factory()->create(['user_id' => $user->id, 'domain' => 'mxscan.me']);

        $this->actingAs($user)
            ->get(route('domains.scan.now.show', $domain))
            ->assertOk()
            ->assertSee('Start scan');
    }
}
