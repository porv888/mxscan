<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\User;
use App\Services\Dmarc\DmarcStatusService;
use Illuminate\Support\Str;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\TestCase;

class DmarcEmptyStateCopyTest extends TestCase
{
    use CreatesPlanUsers;
    use UsesSqliteDmarcSchema;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpPlanTables();
    }

    protected function makeDomain(User $user, string $dmarcRecord, string $token = 'newtoken0000000000000001'): Domain
    {
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'empty-' . Str::random(8) . '.com',
            'dmarc_token' => $token,
            'environment' => 'prod',
            'status' => 'active',
        ]);

        \App\Models\Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'dns',
            'status' => 'finished',
            'facts_json' => ['dmarc' => $dmarcRecord],
            'result_json' => DmarcFixtureBuilder::scanResultJsonWithNativeDmarc(
                $dmarcRecord,
                'dmarc+' . $token . '@mxscan.me',
            ),
            'finished_at' => now(),
        ]);

        return $domain->fresh();
    }

    public function test_not_connected_uses_required_copy(): void
    {
        $user = $this->createPremiumUser();
        $token = 'newtoken0000000000000001';
        $domain = $this->makeDomain($user, 'v=DMARC1; p=quarantine; rua=mailto:other@example.com', $token);

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));
        $response->assertOk();
        $response->assertSee('DMARC is active. Connect MXScan reporting to identify senders and authentication failures.', false);
        $response->assertSee('Connect MXScan reporting', false);
        $response->assertDontSee('0% aligned', false);
    }

    public function test_detected_unlinked_uses_relink_copy(): void
    {
        $user = $this->createPremiumUser();
        $token = 'newtoken0000000000000001';
        $domain = $this->makeDomain(
            $user,
            'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me',
            $token
        );

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));
        $response->assertOk();
        $response->assertSee('MXScan reporting is present, but it is not linked to this domain.', false);
        $response->assertSee('Update your DMARC record', false);
    }

    public function test_connected_waiting_shows_24_48_message(): void
    {
        $user = $this->createPremiumUser();
        $token = 'newtoken0000000000000001';
        $domain = $this->makeDomain(
            $user,
            "v=DMARC1; p=none; rua=mailto:dmarc+{$token}@mxscan.me",
            $token
        );

        $status = app(DmarcStatusService::class)->getStatus($domain);
        $this->assertSame(DmarcStatusService::RUA_LINK_CONNECTED, $status['rua_link_state']);

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));
        $response->assertOk();
        $response->assertSee('Waiting for the first aggregate report. Reports commonly arrive within 24–48 hours.', false);
    }
}
