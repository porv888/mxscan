<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\Plan;
use App\Models\SpfCheck;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class SpfControllerTest extends TestCase
{
    use RefreshDatabase;

    private User $user;
    private Domain $domain;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->user = User::factory()->create([
            'email_verified_at' => now(),
        ]);
        
        $this->domain = Domain::factory()->create([
            'user_id' => $this->user->id,
            'domain' => 'example.com',
            'spf_lookup_count' => 0
        ]);
    }

    public function test_spf_show_requires_authentication(): void
    {
        $response = $this->get(route('spf.show', $this->domain->domain));
        
        $response->assertRedirect(route('login'));
    }

    public function test_spf_show_requires_email_verification(): void
    {
        $unverifiedUser = User::factory()->create([
            'email_verified_at' => null,
        ]);
        
        $response = $this->actingAs($unverifiedUser)
            ->get(route('spf.show', $this->domain->domain));
        
        $response->assertRedirect(route('verification.notice'));
    }

    public function test_spf_show_requires_domain_ownership(): void
    {
        $otherUser = User::factory()->create([
            'email_verified_at' => now(),
        ]);
        
        $response = $this->actingAs($otherUser)
            ->get(route('spf.show', $this->domain->domain));
        
        $response->assertStatus(404);
    }

    public function test_spf_show_displays_page_for_domain_owner(): void
    {
        $response = $this->actingAs($this->user)
            ->get(route('spf.show', $this->domain->domain));
        
        $response->assertStatus(200);
        $response->assertViewIs('domains.spf');
        $response->assertViewHas('domainModel');
        $response->assertSee('SPF Optimizer');
        $response->assertSee($this->domain->domain);
    }

    public function test_spf_show_displays_latest_check_data(): void
    {
        // Create an SPF check
        $spfCheck = SpfCheck::factory()->create([
            'domain_id' => $this->domain->id,
            'domain' => $this->domain->domain,
            'current_record' => 'v=spf1 include:_spf.google.com ~all',
            'lookups_used' => 3,
            'flattened_spf' => 'v=spf1 ip4:192.168.1.1 ~all',
            'warnings' => ['Test warning'],
            'resolved_ips' => ['192.168.1.1'],
            'checked_at' => now(),
        ]);
        
        $response = $this->actingAs($this->user)
            ->get(route('spf.show', $this->domain->domain));
        
        $response->assertStatus(200);
        $response->assertSee('v=spf1 include:_spf.google.com ~all');
        $response->assertSee('3/10');
        $response->assertSee('Test warning');
    }

    public function test_spf_run_requires_authentication(): void
    {
        $response = $this->post(route('spf.run', $this->domain->domain));
        
        $response->assertRedirect(route('login'));
    }

    public function test_spf_run_requires_domain_ownership(): void
    {
        $otherUser = User::factory()->create([
            'email_verified_at' => now(),
        ]);
        
        $response = $this->actingAs($otherUser)
            ->post(route('spf.run', $this->domain->domain));
        
        $response->assertStatus(404);
    }

    public function test_spf_run_dispatches_job_and_redirects(): void
    {
        $response = $this->actingAs($this->user)
            ->post(route('spf.run', $this->domain->domain));
        
        $response->assertRedirect(route('spf.show', $this->domain->domain));
        $response->assertSessionHas('success');
    }

    public function test_spf_show_displays_no_checks_message_when_empty(): void
    {
        $response = $this->actingAs($this->user)
            ->get(route('spf.show', $this->domain->domain));
        
        $response->assertStatus(200);
        $response->assertSee('No SPF checks yet');
        $response->assertSee('Run your first SPF check');
    }
}
