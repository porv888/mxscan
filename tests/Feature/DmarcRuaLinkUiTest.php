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

    public function test_detected_unlinked_setup_ui_copy_and_dns_panel(): void
    {
        $user = User::factory()->create();
        $token = 'newtoken0000000000000001';
        $input = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:dmarc+oldtoken@mxscan.me,mailto:rua@dmarc.brevo.com';
        $domain = $this->makeDomainWithScan($user, $input, $token);

        $expectedUpdated = 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+' . $token . '@mxscan.me';
        $warning = 'MXScan reporting is present, but it is not linked to this domain.';

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));
        $html = $response->getContent();

        $response->assertOk();
        $this->assertSame(1, substr_count($html, $warning));
        $response->assertSee('Replace your current DMARC TXT value with the updated value below.', false);
        $response->assertSee('Update your DMARC record', false);
        $response->assertSee('This removes old MXScan reporting addresses, keeps external reporting destinations, and adds the correct MXScan address for this domain.', false);

        $response->assertSee('TXT', false);
        $response->assertSee('_dmarc.' . $domain->domain, false);
        $response->assertSee('Replace existing value', false);
        $response->assertSee($expectedUpdated, false);
        $response->assertSee('Do not create a second DMARC record. Replace the value of the existing TXT record.', false);

        $response->assertSee('Copy updated record', false);
        $response->assertSee('I’ve updated DNS — Check again', false);
        $response->assertSee('mx-btn-primary', false);
        $response->assertSee('mx-btn-secondary', false);
        $response->assertDontSee('Relink MXScan reporting', false);
        $response->assertDontSee('I Added It — Check DNS', false);

        $response->assertSee('MXScan will make these changes:', false);
        $response->assertSee('Removed:', false);
        $response->assertSee('dmarc@mxscan.me', false);
        $response->assertSee('dmarc+oldtoken@mxscan.me', false);
        $response->assertSee('Preserved:', false);
        $response->assertSee('rua@dmarc.brevo.com', false);
        $response->assertSee('Added:', false);
        $response->assertSee('dmarc+' . $token . '@mxscan.me', false);

        $response->assertSee('Show current record and technical comparison', false);
        $this->assertStringNotContainsString('id="dmarc-tech-comparison" open', $html);
        $this->assertMatchesRegularExpression('/aria-expanded="false"|:aria-expanded="open\.toString\(\)"/', $html);

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
        $this->assertContains('dmarc@mxscan.me', $update['removed_recipients']);
        $this->assertContains('rua@dmarc.brevo.com', $update['preserved_recipients']);
        $this->assertContains('dmarc+' . $token . '@mxscan.me', $update['added_recipients']);
    }

    public function test_failed_verification_keeps_setup_instructions(): void
    {
        $user = User::factory()->create();
        $token = 'newtoken0000000000000001';
        $input = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:rua@dmarc.brevo.com';
        $domain = $this->makeDomainWithScan($user, $input, $token);

        $response = $this->actingAs($user)->get(route('dmarc.show', $domain));
        $response->assertOk();
        $response->assertSee('Update your DMARC record', false);
        $response->assertSee('Copy updated record', false);
        $response->assertSee('I’ve updated DNS — Check again', false);
        $response->assertSee('The updated record was not detected yet.', false);
    }
}
