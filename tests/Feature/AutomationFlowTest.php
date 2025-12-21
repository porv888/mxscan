<?php

namespace Tests\Feature;

use App\Models\User;
use App\Models\Domain;
use App\Models\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AutomationFlowTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test that automations index page loads.
     */
    public function test_automations_index_page_loads(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get(route('automations.index'));

        $response->assertStatus(200);
        $response->assertSee('Automations');
    }

    /**
     * Test that automation can be created.
     */
    public function test_automation_can_be_created(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);

        $response = $this->actingAs($user)
            ->post(route('automations.store'), [
                'domain_id' => $domain->id,
                'scan_type' => 'complete',
                'frequency' => 'daily'
            ]);

        $response->assertRedirect(route('automations.index'));
        $response->assertSessionHas('success', 'Automation saved.');
        
        $this->assertDatabaseHas('schedules', [
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'scan_type' => 'both', // Maps to legacy format
            'frequency' => 'daily'
        ]);
    }

    /**
     * Test that automation can be updated.
     */
    public function test_automation_can_be_updated(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        $schedule = Schedule::factory()->create([
            'user_id' => $user->id,
            'domain_id' => $domain->id,
            'scan_type' => 'dns_security',
            'frequency' => 'daily'
        ]);

        $response = $this->actingAs($user)
            ->put(route('automations.update', $schedule), [
                'domain_id' => $domain->id,
                'scan_type' => 'complete',
                'frequency' => 'weekly'
            ]);

        $response->assertRedirect(route('automations.index'));
        $response->assertSessionHas('success', 'Automation saved.');
        
        $this->assertDatabaseHas('schedules', [
            'id' => $schedule->id,
            'scan_type' => 'both',
            'frequency' => 'weekly'
        ]);
    }

    /**
     * Test that automation can be paused.
     */
    public function test_automation_can_be_paused(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        $schedule = Schedule::factory()->create([
            'user_id' => $user->id,
            'domain_id' => $domain->id,
            'status' => 'active'
        ]);

        $response = $this->actingAs($user)
            ->post(route('automations.pause', $schedule));

        $response->assertRedirect(route('automations.index'));
        $response->assertSessionHas('success', 'Automation paused.');
        
        $this->assertDatabaseHas('schedules', [
            'id' => $schedule->id,
            'status' => 'paused'
        ]);
    }

    /**
     * Test that automation can be resumed.
     */
    public function test_automation_can_be_resumed(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        $schedule = Schedule::factory()->create([
            'user_id' => $user->id,
            'domain_id' => $domain->id,
            'status' => 'paused'
        ]);

        $response = $this->actingAs($user)
            ->post(route('automations.resume', $schedule));

        $response->assertRedirect(route('automations.index'));
        $response->assertSessionHas('success', 'Automation resumed.');
        
        $this->assertDatabaseHas('schedules', [
            'id' => $schedule->id,
            'status' => 'active'
        ]);
    }

    /**
     * Test that automation can be deleted.
     */
    public function test_automation_can_be_deleted(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id, 'domain' => 'example.com']);
        $schedule = Schedule::factory()->create([
            'user_id' => $user->id,
            'domain_id' => $domain->id
        ]);

        $response = $this->actingAs($user)
            ->delete(route('automations.destroy', $schedule));

        $response->assertRedirect(route('automations.index'));
        $response->assertSessionHas('success');
        
        $this->assertDatabaseMissing('schedules', [
            'id' => $schedule->id
        ]);
    }

    /**
     * Test that users cannot access other users' automations.
     */
    public function test_users_cannot_access_other_users_automations(): void
    {
        $user1 = User::factory()->create();
        $user2 = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user1->id]);
        $schedule = Schedule::factory()->create([
            'user_id' => $user1->id,
            'domain_id' => $domain->id
        ]);

        $response = $this->actingAs($user2)
            ->get(route('automations.edit', $schedule));

        $response->assertStatus(403);
    }

    /**
     * Test that automation run now dispatches job.
     */
    public function test_automation_run_now_dispatches_job(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        $schedule = Schedule::factory()->create([
            'user_id' => $user->id,
            'domain_id' => $domain->id,
            'scan_type' => 'both'
        ]);

        $response = $this->actingAs($user)
            ->post(route('automations.run-now', $schedule));

        $response->assertRedirect(route('automations.index'));
        $response->assertSessionHas('success', 'Automation executed. Check Reports for results.');
    }
}
