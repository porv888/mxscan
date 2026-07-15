<?php

namespace Tests\Unit\Services\Dmarc;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\Dmarc\DmarcStatusService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\TestCase;

class DmarcStatusServiceAnalysisReadTest extends TestCase
{
    use RefreshDatabase;

    public function test_reads_native_analysis_for_rua_classification(): void
    {
        $user = \App\Models\User::factory()->create();
        $domain = Domain::factory()->create([
            'user_id' => $user->id,
            'domain' => 'analysis-read.test',
            'dmarc_token' => 'tokentest00000000000000001',
        ]);

        $analysis = DmarcFixtureBuilder::nativeAnalysis([
            'aggregate_reporting' => [
                'configured' => true,
                'destinations' => [[
                    'raw_uri' => 'mailto:dmarc+tokentest00000000000000001@mxscan.me',
                    'normalized_destination' => 'dmarc+tokentest00000000000000001@mxscan.me',
                    'destination_domain' => 'mxscan.me',
                    'internal' => true,
                    'authorization_required' => false,
                    'authorization_status' => 'not_required',
                ]],
                'mxscan_expectation' => [
                    'expected_address' => 'dmarc+tokentest00000000000000001@mxscan.me',
                    'present' => true,
                    'other_valid_destination_exists' => false,
                ],
            ],
        ], 'v=DMARC1; p=quarantine; rua=mailto:dmarc+tokentest00000000000000001@mxscan.me');

        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'full',
            'status' => 'finished',
            'result_json' => [
                'dmarc' => [
                    'analysis' => $analysis,
                    'ui_state' => 'pass',
                ],
            ],
            'finished_at' => now(),
        ]);

        $status = app(DmarcStatusService::class)->getStatus($domain->fresh());

        $this->assertSame(DmarcStatusService::RUA_LINK_CONNECTED, $status['rua_link_state']);
        $this->assertTrue($status['has_canonical_mxscan_rua']);
    }
}
