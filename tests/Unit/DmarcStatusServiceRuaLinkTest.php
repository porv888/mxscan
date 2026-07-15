<?php

namespace Tests\Unit;

use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\Dmarc\DmarcStatusService;
use Illuminate\Support\Str;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\TestCase;

class DmarcStatusServiceRuaLinkTest extends TestCase
{
    use UsesSqliteDmarcSchema;

    protected DmarcStatusService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->service = app(DmarcStatusService::class);
    }

    protected function makeDomainWithScan(string $dmarcRecord, array $domainAttrs = [], string $scanStatus = 'finished'): Domain
    {
        $user = User::factory()->create();
        $token = $domainAttrs['dmarc_token'] ?? 'newtoken0000000000000001';
        $domain = Domain::create(array_merge([
            'user_id' => $user->id,
            'domain' => 'example-' . Str::random(8) . '.com',
            'dmarc_token' => $token,
        ], $domainAttrs));

        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'dns',
            'status' => $scanStatus,
            'facts_json' => ['dmarc' => $dmarcRecord],
            'result_json' => DmarcFixtureBuilder::scanResultJsonWithNativeDmarc(
                $dmarcRecord,
                'dmarc+' . $token . '@mxscan.me',
            ),
            'finished_at' => now(),
        ]);

        return $domain->fresh();
    }

    protected function makeLegacyDomainWithScan(string $dmarcRecord, array $domainAttrs = [], string $scanStatus = 'finished'): Domain
    {
        $user = User::factory()->create();
        $domain = Domain::create(array_merge([
            'user_id' => $user->id,
            'domain' => 'legacy-' . Str::random(8) . '.com',
            'dmarc_token' => 'newtoken0000000000000001',
        ], $domainAttrs));

        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'dns',
            'status' => $scanStatus,
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

    public function test_old_mxscan_tokens_are_detected_unlinked(): void
    {
        $record = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:dmarc+oldtoken@mxscan.me,mailto:rua@dmarc.brevo.com';
        $domain = $this->makeDomainWithScan($record);

        $status = $this->service->getStatus($domain);

        $this->assertSame(DmarcStatusService::STATUS_ENABLED_NOT_MXSCAN, $status['status']);
        $this->assertSame(DmarcStatusService::RUA_LINK_DETECTED_UNLINKED, $status['rua_link_state']);
        $this->assertSame('MXScan reporting is present, but it is not linked to this domain.', $status['rua_link_label']);
        $this->assertSame('Relink MXScan reporting', $status['rua_link_cta']);
        $this->assertSame('relink', $status['cta_action']);
        $this->assertTrue($status['has_any_mxscan_rua']);
        $this->assertFalse($status['has_canonical_mxscan_rua']);
        $this->assertFalse($status['has_mxscan_rua']);
    }

    public function test_external_rua_only_is_not_connected(): void
    {
        $domain = $this->makeDomainWithScan('v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com');

        $status = $this->service->getStatus($domain);

        $this->assertSame(DmarcStatusService::RUA_LINK_NOT_CONNECTED, $status['rua_link_state']);
        $this->assertSame('DMARC is active. Connect MXScan reporting to identify senders and authentication failures.', $status['rua_link_label']);
        $this->assertSame('Connect MXScan reporting', $status['rua_link_cta']);
        $this->assertSame('add_rua', $status['cta_action']);
        $this->assertFalse($status['has_any_mxscan_rua']);
    }

    public function test_canonical_present_without_reports_is_connected_waiting(): void
    {
        $token = 'newtoken0000000000000001';
        $domain = $this->makeDomainWithScan(
            "v=DMARC1; p=none; rua=mailto:dmarc+{$token}@mxscan.me",
            ['dmarc_token' => $token]
        );

        $status = $this->service->getStatus($domain);

        $this->assertSame(DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING, $status['status']);
        $this->assertSame(DmarcStatusService::RUA_LINK_CONNECTED, $status['rua_link_state']);
        $this->assertSame('MXScan reporting connected', $status['rua_link_label']);
        $this->assertNull($status['rua_link_cta']);
        $this->assertTrue($status['has_canonical_mxscan_rua']);
        $this->assertTrue($status['has_mxscan_rua']);
    }

    public function test_verified_at_alone_does_not_make_connected(): void
    {
        $domain = $this->makeDomainWithScan(
            'v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com',
            ['dmarc_rua_verified_at' => now()]
        );

        $status = $this->service->getStatus($domain);

        $this->assertFalse($status['has_mxscan_rua']);
        $this->assertFalse($status['has_canonical_mxscan_rua']);
        $this->assertSame(DmarcStatusService::RUA_LINK_NOT_CONNECTED, $status['rua_link_state']);
    }

    public function test_get_updated_dmarc_record_required_example(): void
    {
        $token = 'newtoken0000000000000001';
        $input = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:dmarc+oldtoken@mxscan.me,mailto:rua@dmarc.brevo.com';
        $domain = $this->makeDomainWithScan($input, ['dmarc_token' => $token]);

        $update = $this->service->getUpdatedDmarcRecord($domain);

        $this->assertNotNull($update);
        $this->assertSame('relink_rua', $update['action']);
        $this->assertSame(
            'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+' . $token . '@mxscan.me',
            $update['updated']
        );
        $this->assertSame(1, preg_match_all('/@mxscan\.me/i', $update['updated']));
    }

    public function test_legacy_completed_scan_status_is_accepted(): void
    {
        $token = 'newtoken0000000000000001';
        $domain = $this->makeLegacyDomainWithScan(
            "v=DMARC1; p=none; rua=mailto:dmarc+{$token}@mxscan.me",
            ['dmarc_token' => $token],
            'completed',
        );

        $status = $this->service->getStatus($domain);

        $this->assertTrue($status['has_dmarc_record']);
        $this->assertSame(DmarcStatusService::RUA_LINK_CONNECTED, $status['rua_link_state']);
    }

    public function test_preserves_existing_get_status_keys(): void
    {
        $domain = $this->makeDomainWithScan('v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com');
        $status = $this->service->getStatus($domain);

        foreach ([
            'status', 'label', 'badge_color', 'helper_text', 'cta_text', 'cta_action',
            'has_dmarc_record', 'has_rua', 'has_mxscan_rua', 'has_reports', 'is_stale',
            'last_report_at', 'last_dns_check_at', 'checklist',
            'rua_link_state', 'rua_link_label', 'rua_link_cta',
            'has_any_mxscan_rua', 'has_canonical_mxscan_rua',
        ] as $key) {
            $this->assertArrayHasKey($key, $status);
        }
    }
}
