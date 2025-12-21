<?php

namespace Tests\Feature;

use App\Models\User;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ScanReportFlowTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test that a scan redirects to reports page after completion.
     */
    public function test_scan_redirects_to_reports_after_completion(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);

        $response = $this->actingAs($user)
            ->post(route('domains.scan.now', $domain), [
                'mode' => 'dns'
            ]);

        // Should redirect to reports.show
        $response->assertRedirect();
        $this->assertTrue(str_contains($response->headers->get('Location'), '/reports/'));
        
        // Verify scan was created
        $this->assertDatabaseHas('scans', [
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'dns',
            'status' => 'finished'
        ]);
    }

    /**
     * Test that reports index shows scans.
     */
    public function test_reports_index_shows_scans(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => 'finished',
            'score' => 85
        ]);

        $response = $this->actingAs($user)->get(route('reports.index'));

        $response->assertStatus(200);
        $response->assertSee($domain->domain);
        $response->assertSee('85');
    }

    /**
     * Test that reports can be filtered by domain.
     */
    public function test_reports_can_be_filtered_by_domain(): void
    {
        $user = User::factory()->create();
        $domain1 = Domain::factory()->create(['user_id' => $user->id, 'domain' => 'example1.com']);
        $domain2 = Domain::factory()->create(['user_id' => $user->id, 'domain' => 'example2.com']);
        
        Scan::factory()->create([
            'domain_id' => $domain1->id,
            'user_id' => $user->id,
            'type' => 'full'
        ]);
        
        Scan::factory()->create([
            'domain_id' => $domain2->id,
            'user_id' => $user->id,
            'type' => 'full'
        ]);

        $response = $this->actingAs($user)
            ->get(route('reports.index', ['domain_id' => $domain1->id]));

        $response->assertStatus(200);
        $response->assertSee('example1.com');
        $response->assertDontSee('example2.com');
    }

    /**
     * Test that reports can be filtered by scan type.
     */
    public function test_reports_can_be_filtered_by_scan_type(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        
        Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full'
        ]);
        
        Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'blacklist'
        ]);

        $response = $this->actingAs($user)
            ->get(route('reports.index', ['scan_type' => 'blacklist']));

        $response->assertStatus(200);
        $response->assertSee('Blacklist Only');
    }

    /**
     * Test that report detail page shows scan results.
     */
    public function test_report_detail_shows_scan_results(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => 'finished',
            'score' => 90
        ]);

        $response = $this->actingAs($user)->get(route('reports.show', $scan));

        $response->assertStatus(200);
        $response->assertSee($domain->domain);
        $response->assertSee('90');
    }

    /**
     * Test that users cannot access other users' reports.
     */
    public function test_users_cannot_access_other_users_reports(): void
    {
        $user1 = User::factory()->create();
        $user2 = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user1->id]);
        
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user1->id,
            'type' => 'full'
        ]);

        $response = $this->actingAs($user2)->get(route('reports.show', $scan));

        $response->assertStatus(403);
    }

    /**
     * Test CSV export functionality.
     */
    public function test_reports_can_be_exported_to_csv(): void
    {
        $user = User::factory()->create();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        
        Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'score' => 85
        ]);

        $response = $this->actingAs($user)->get(route('reports.export'));

        $response->assertStatus(200);
        $response->assertHeader('content-type', 'text/csv; charset=UTF-8');
        $this->assertStringContainsString($domain->domain, $response->getContent());
    }
}
