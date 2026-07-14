<?php

namespace Tests\Unit;

use App\Models\Domain;
use App\Models\User;
use App\Rules\WithinDomainLimit;
use App\Services\Entitlement\EntitlementFeature;
use App\Services\Entitlement\EntitlementService;
use Illuminate\Support\Facades\Validator;
use Tests\Concerns\CreatesPlanUsers;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class EntitlementServiceTest extends TestCase
{
    use UsesSqliteDmarcSchema;
    use CreatesPlanUsers;

    private EntitlementService $entitlements;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpPlanTables();
        config(['plans.limits.freemium' => 1]);
        $this->entitlements = app(EntitlementService::class);
    }

    public function test_free_domain_limit_is_one(): void
    {
        $user = User::factory()->create();

        $this->assertSame(1, $this->entitlements->domainLimit($user));
    }

    public function test_premium_domain_limit_is_ten(): void
    {
        $user = $this->createPremiumUser();

        $this->assertSame(10, $this->entitlements->domainLimit($user));
    }

    public function test_cannot_add_second_domain_on_free_plan(): void
    {
        $user = User::factory()->create();
        Domain::create([
            'user_id' => $user->id,
            'domain' => 'first.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000001',
        ]);

        $validator = Validator::make(
            ['domain' => 'second.example.com'],
            ['domain' => [new WithinDomainLimit($user)]]
        );

        $this->assertTrue($validator->fails());
        $this->assertStringContainsString('1 domain', $validator->errors()->first('domain'));
    }

    public function test_subdomain_bypass_removed(): void
    {
        $user = User::factory()->create();
        Domain::create([
            'user_id' => $user->id,
            'domain' => 'example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000002',
        ]);

        $validator = Validator::make(
            ['domain' => 'app.example.com'],
            ['domain' => [new WithinDomainLimit($user)]]
        );

        $this->assertTrue($validator->fails());
    }

    public function test_oldest_domain_is_active_for_multi_domain_free_user(): void
    {
        $user = User::factory()->create();
        $oldest = Domain::create([
            'user_id' => $user->id,
            'domain' => 'oldest.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000003',
            'created_at' => now()->subDays(10),
        ]);
        $middle = Domain::create([
            'user_id' => $user->id,
            'domain' => 'middle.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000004',
            'created_at' => now()->subDays(5),
        ]);
        $newest = Domain::create([
            'user_id' => $user->id,
            'domain' => 'newest.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000005',
            'created_at' => now(),
        ]);

        $this->assertTrue($this->entitlements->isDomainActive($user, $oldest));
        $this->assertFalse($this->entitlements->isDomainActive($user, $middle));
        $this->assertFalse($this->entitlements->isDomainActive($user, $newest));
        $this->assertTrue($this->entitlements->isDomainLocked($user, $newest));
    }

    public function test_free_user_can_manual_full_scan_on_active_domain_only(): void
    {
        $user = User::factory()->create();
        $active = Domain::create([
            'user_id' => $user->id,
            'domain' => 'active.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000006',
            'created_at' => now()->subDay(),
        ]);
        $locked = Domain::create([
            'user_id' => $user->id,
            'domain' => 'locked.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000007',
            'created_at' => now(),
        ]);

        $this->assertTrue($this->entitlements->canOnDomain($user, $active, EntitlementFeature::MANUAL_FULL_SCAN));
        $this->assertFalse($this->entitlements->canOnDomain($user, $locked, EntitlementFeature::MANUAL_FULL_SCAN));
    }

    public function test_free_user_cannot_use_partial_scan(): void
    {
        $user = User::factory()->create();
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'active.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000008',
        ]);

        $this->assertFalse($this->entitlements->can($user, EntitlementFeature::PARTIAL_SCAN));
        $this->assertFalse($this->entitlements->canOnDomain($user, $domain, EntitlementFeature::PARTIAL_SCAN));
    }

    public function test_free_user_cannot_access_premium_features(): void
    {
        $user = User::factory()->create();

        $this->assertFalse($this->entitlements->can($user, EntitlementFeature::STANDALONE_TOOLS));
        $this->assertFalse($this->entitlements->can($user, EntitlementFeature::AUTOMATIONS));
        $this->assertFalse($this->entitlements->can($user, EntitlementFeature::DMARC_ACTIVITY));
    }

    public function test_premium_user_has_premium_features(): void
    {
        $user = $this->createPremiumUser();
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'paid.example.com',
            'environment' => 'prod',
            'status' => 'active',
            'dmarc_token' => 'tokentest00000000000000009',
        ]);

        $this->assertTrue($this->entitlements->can($user, EntitlementFeature::AUTOMATIONS));
        $this->assertTrue($this->entitlements->canOnDomain($user, $domain, EntitlementFeature::PARTIAL_SCAN));
        $this->assertTrue($this->entitlements->can($user, EntitlementFeature::DMARC_ACTIVITY));
    }
}
