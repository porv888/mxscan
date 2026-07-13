<?php

namespace Tests\Feature;

use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\Dmarc\DmarcStatusService;
use Illuminate\Support\Str;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class DmarcRuaLinkUiTest extends TestCase
{
    use UsesSqliteDmarcSchema;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
    }

    protected function makeDomainWithScan(User $user, string $dmarcRecord, string $token = 'newtoken0000000000000001'): Domain
    {
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'ui-' . Str::random(8) . '.com',
            'dmarc_token' => $token,
        ]);

        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'dns',
            'status' => 'finished',
            'facts_json' => ['dmarc' => $dmarcRecord],
            'result_json' => [
                'dns' => [
                    'records' => [
                        'DMARC' => [
                            'status' => 'found',
                            'data' => $dmarcRecord,
                        ],
                    ],
                ],
            ],
            'finished_at' => now(),
        ]);

        return $domain->fresh();
    }

    public function test_connected_label_on_show_page(): void
    {
        $user = User::factory()->create();
        $token = 'newtoken0000000000000001';
        $domain = $this->makeDomainWithScan(
            $user,
            "v=DMARC1; p=none; rua=mailto:dmarc+{$token}@mxscan.me",
            $token
        );

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));

        $response->assertOk();
        $response->assertSee('MXScan reporting connected', false);
        $response->assertDontSee('Relink MXScan reporting', false);
        $response->assertDontSee('Connect MXScan reporting', false);
    }

    public function test_detected_unlinked_shows_relink_cta_and_single_mxscan_record(): void
    {
        $user = User::factory()->create();
        $token = 'newtoken0000000000000001';
        $input = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:dmarc+oldtoken@mxscan.me,mailto:rua@dmarc.brevo.com';
        $domain = $this->makeDomainWithScan($user, $input, $token);

        $expectedUpdated = 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+' . $token . '@mxscan.me';

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));

        $response->assertOk();
        $response->assertSee('MXScan reporting is present, but it is not linked to this domain.', false);
        $response->assertSee('Relink MXScan reporting', false);
        $response->assertSee($expectedUpdated, false);
        $this->assertGreaterThanOrEqual(1, substr_count($response->getContent(), $expectedUpdated));
        $this->assertSame(1, preg_match_all('/@mxscan\.me/i', $expectedUpdated));
    }

    public function test_not_connected_shows_connect_cta(): void
    {
        $user = User::factory()->create();
        $domain = $this->makeDomainWithScan(
            $user,
            'v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com'
        );

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));

        $response->assertOk();
        $response->assertSee('DMARC is active. Connect MXScan reporting to identify senders and authentication failures.', false);
        $response->assertSee('Connect MXScan reporting', false);

        $status = app(DmarcStatusService::class)->getStatus($domain);
        $this->assertSame(DmarcStatusService::RUA_LINK_NOT_CONNECTED, $status['rua_link_state']);
    }

    public function test_updated_record_does_not_append_extra_mxscan_address(): void
    {
        $user = User::factory()->create();
        $token = 'newtoken0000000000000001';
        $input = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:dmarc+f162461412858183e0eb489f@mxscan.me,mailto:rua@dmarc.brevo.com';
        $domain = $this->makeDomainWithScan($user, $input, $token);

        $expectedUpdated = 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+' . $token . '@mxscan.me';

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));

        $response->assertOk();
        $response->assertSee($expectedUpdated, false);
        $update = app(DmarcStatusService::class)->getUpdatedDmarcRecord($domain);
        $this->assertSame($expectedUpdated, $update['updated']);
        $this->assertSame(1, preg_match_all('/@mxscan\.me/i', $update['updated']));
        $this->assertStringNotContainsString('dmarc+f162461412858183e0eb489f@mxscan.me', $update['updated']);
    }
}
