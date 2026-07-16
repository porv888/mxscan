<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Remediation\SenderEvidenceSynchronizer;
use App\Domain\EmailSecurity\Remediation\SpfRemediationBuilder;
use App\Models\Domain;
use App\Models\DomainSender;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Concerns\CreatesPlanUsers;
use Tests\TestCase;

class TechnicalRemediationTest extends TestCase
{
    use CreatesPlanUsers;
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpPlanTables();
    }

    public function test_mx_evidence_is_persisted_pending_and_never_auto_confirmed(): void
    {
        $user = $this->createPremiumUser();
        $domain = Domain::factory()->create(['user_id' => $user->id, 'domain' => 'mxscan.me']);
        $fixture = json_decode(
            file_get_contents(base_path('tests/Fixtures/EmailSecurity/mxscan-me-scan-result.json')),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        app(SenderEvidenceSynchronizer::class)->sync($domain, $fixture);

        $senders = $domain->senders()->whereIn('mechanism', ['ip4', 'ip6'])->get();
        $this->assertCount(2, $senders);
        $this->assertTrue($senders->every(fn ($sender) => $sender->confirmation_status === DomainSender::STATUS_PENDING));
        $this->assertTrue($senders->every(fn ($sender) => $sender->confidence === DomainSender::CONFIDENCE_LIKELY));
        $this->assertSame(
            ['2001:1af8:5301:131:1c00:62ff:fe00:1efc', '89.149.243.245'],
            $senders->pluck('value')->sort()->values()->all(),
        );
    }

    public function test_soft_fail_scores_fifteen_and_hard_fail_requires_complete_confirmation(): void
    {
        $user = $this->createPremiumUser();
        $domain = Domain::factory()->create(['user_id' => $user->id]);
        $rows = [
            $this->sender('ip4', '203.0.113.10', DomainSender::STATUS_CONFIRMED),
            $this->sender('ip6', '2001:db8::10', DomainSender::STATUS_PENDING),
        ];
        $builder = app(SpfRemediationBuilder::class);

        $starting = $builder->build($domain, '~all', $rows)->toArray();
        $blockedHardFail = $builder->build($domain, '-all', $rows)->toArray();
        $rows[1]['confirmation_status'] = DomainSender::STATUS_CONFIRMED;
        $ready = $builder->build($domain, '-all', $rows)->toArray();

        $this->assertSame(15, $starting['score']);
        $this->assertStringEndsWith('~all', $starting['record']);
        $this->assertSame('~all', $blockedHardFail['policy']);
        $this->assertSame(15, $blockedHardFail['score']);
        $this->assertSame('-all', $ready['policy']);
        $this->assertSame(20, $ready['score']);
        $this->assertSame('Ready to publish', $ready['state']);
    }

    public function test_sender_choices_and_dns_provider_are_saved_per_domain(): void
    {
        $user = $this->createPremiumUser();
        $domain = Domain::factory()->create(['user_id' => $user->id]);

        $response = $this->actingAs($user)->postJson(route('domains.remediation.spf.save', $domain), [
            'policy' => '~all',
            'dns_provider' => 'cloudflare',
            'senders' => [$this->sender('ip4', '203.0.113.20', DomainSender::STATUS_CONFIRMED)],
        ]);

        $response->assertOk()->assertJsonPath('spf.score', 15);
        $this->assertDatabaseHas('domain_senders', [
            'domain_id' => $domain->id,
            'mechanism' => 'ip4',
            'value' => '203.0.113.20',
            'confirmation_status' => DomainSender::STATUS_CONFIRMED,
            'confirmed_by' => $user->id,
        ]);
        $this->assertSame('cloudflare', $domain->fresh()->dns_provider);
        $this->assertNotNull($domain->fresh()->dns_provider_confirmed_at);
    }

    /**
     * @return array<string, mixed>
     */
    private function sender(string $mechanism, string $value, string $status): array
    {
        return [
            'sender_type' => 'own_server',
            'provider' => null,
            'mechanism' => $mechanism,
            'value' => $value,
            'source' => DomainSender::SOURCE_DETECTED,
            'confidence' => $status === DomainSender::STATUS_CONFIRMED
                ? DomainSender::CONFIDENCE_CONFIRMED
                : DomainSender::CONFIDENCE_LIKELY,
            'confirmation_status' => $status,
            'is_active' => true,
        ];
    }
}
