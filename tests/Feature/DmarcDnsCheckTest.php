<?php

namespace Tests\Feature;

use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcRecordDiscovery;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\Dmarc\DmarcStatusService;
use Illuminate\Support\Str;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\Support\EmailSecurity\FakeDmarcDnsResolver;
use Tests\TestCase;

class DmarcDnsCheckTest extends TestCase
{
    use CreatesPlanUsers;
    use UsesSqliteDmarcSchema;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpPlanTables();
    }

    protected function makeDomainWithStaleScan(User $user, string $token): Domain
    {
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'mxscan.me',
            'dmarc_token' => $token,
        ]);

        $staleRecord = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:dmarc+oldtoken@mxscan.me,mailto:rua@dmarc.brevo.com';

        Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'dns',
            'status' => 'finished',
            'facts_json' => ['dmarc' => $staleRecord],
            'result_json' => [
                'dns' => [
                    'records' => [
                        'DMARC' => [
                            'status' => 'found',
                            'data' => $staleRecord,
                        ],
                    ],
                ],
            ],
            'finished_at' => now()->subMonths(6),
        ]);

        return $domain->fresh();
    }

    public function test_check_dns_ignores_stale_scan_and_uses_fresh_dns(): void
    {
        $user = $this->createPremiumUser();
        $token = '718d719760053ef030649861';
        $domain = $this->makeDomainWithStaleScan($user, $token);
        $canonical = 'dmarc+' . $token . '@mxscan.me';
        $liveRecord = 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:' . $canonical;

        $statusBefore = app(DmarcStatusService::class)->getStatus($domain);
        $this->assertSame(DmarcStatusService::RUA_LINK_DETECTED_UNLINKED, $statusBefore['rua_link_state']);

        $this->bindDiscovery($domain->domain, $liveRecord);

        $response = $this->actingAs($user)->postJson(route('dmarc.check-dns', $domain));

        $response->assertOk();
        $response->assertJson([
            'success' => true,
            'is_configured' => true,
            'has_canonical_mxscan_rua' => true,
            'has_any_mxscan_rua' => true,
            'rua_link_state' => DmarcStatusService::RUA_LINK_CONNECTED,
        ]);

        $domain->refresh();
        $this->assertNotNull($domain->dmarc_rua_verified_at);
        $this->assertSame($liveRecord, $domain->dmarc_dns_record);

        $statusAfter = app(DmarcStatusService::class)->getStatus($domain);
        $this->assertSame(DmarcStatusService::RUA_LINK_CONNECTED, $statusAfter['rua_link_state']);
        $this->assertTrue($statusAfter['has_canonical_mxscan_rua']);
        $this->assertSame('MXScan reporting connected', $statusAfter['rua_link_label']);
        $this->assertNull($statusAfter['rua_link_cta']);
        $this->assertSame(DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING, $statusAfter['status']);
    }

    public function test_get_status_prefers_verified_dns_snapshot_over_stale_scan(): void
    {
        $user = $this->createPremiumUser();
        $token = '718d719760053ef030649861';
        $domain = $this->makeDomainWithStaleScan($user, $token);
        $canonical = 'dmarc+' . $token . '@mxscan.me';
        $liveRecord = 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:' . $canonical;

        $domain->update([
            'dmarc_rua_verified_at' => now(),
            'dmarc_dns_record' => $liveRecord,
        ]);

        $status = app(DmarcStatusService::class)->getStatus($domain->fresh());

        $this->assertSame(DmarcStatusService::RUA_LINK_CONNECTED, $status['rua_link_state']);
        $this->assertTrue($status['has_canonical_mxscan_rua']);
    }

    public function test_failed_check_returns_diagnostics_without_exception_trace(): void
    {
        $user = $this->createPremiumUser();
        $token = '718d719760053ef030649861';
        $domain = $this->makeDomainWithStaleScan($user, $token);

        $this->bindDiscovery($domain->domain, null);

        $response = $this->actingAs($user)->postJson(route('dmarc.check-dns', $domain));

        $response->assertOk();
        $response->assertJson([
            'has_canonical_mxscan_rua' => false,
            'rua_link_state' => DmarcStatusService::RUA_LINK_NOT_CONNECTED,
        ]);
        $response->assertJsonPath(
            'message',
            'MXScan checked _dmarc.mxscan.me but did not find the expected reporting address.'
        );
        $response->assertJsonPath('dns_diagnostics.hostname', '_dmarc.mxscan.me');
        $response->assertJsonPath('dns_diagnostics.expected_rua_recipient', 'dmarc+' . $token . '@mxscan.me');
        $this->assertArrayNotHasKey('exception', $response->json());
        $this->assertArrayNotHasKey('trace', $response->json());
    }

    private function bindDiscovery(string $domainName, ?string $record): void
    {
        $hostname = '_dmarc.' . $domainName;
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setRecord($hostname, $record);

        $this->app->instance(DmarcDnsResolverInterface::class, $resolver);
        $this->app->instance(
            DmarcRecordDiscovery::class,
            new DmarcRecordDiscovery($resolver),
        );
        $this->app->forgetInstance(DmarcStatusService::class);
    }
}
