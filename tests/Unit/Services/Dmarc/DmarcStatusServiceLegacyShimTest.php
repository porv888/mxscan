<?php

namespace Tests\Unit\Services\Dmarc;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\Dmarc\DmarcStatusService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

class DmarcStatusServiceLegacyShimTest extends TestCase
{
    use RefreshDatabase;

    public function test_legacy_scan_without_analysis_uses_enriched_shim(): void
    {
        $user = \App\Models\User::factory()->create();
        $domain = Domain::factory()->create([
            'user_id' => $user->id,
            'domain' => 'legacy-shim.test',
            'dmarc_token' => 'newtoken0000000000000001',
        ]);

        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'dns',
            'status' => 'finished',
            'facts_json' => ['dmarc' => 'v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com'],
            'result_json' => [
                'dns' => [
                    'records' => [
                        'DMARC' => [
                            'status' => 'found',
                            'data' => 'v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com',
                        ],
                    ],
                ],
            ],
            'finished_at' => now(),
        ]);

        $status = app(DmarcStatusService::class)->getStatus($domain->fresh());

        $this->assertTrue($status['has_dmarc_record']);
        $this->assertTrue($status['has_rua']);
        $this->assertSame(DmarcStatusService::RUA_LINK_NOT_CONNECTED, $status['rua_link_state']);
    }
}
