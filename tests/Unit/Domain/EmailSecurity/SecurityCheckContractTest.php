<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck;
use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcCheck;
use App\Domain\EmailSecurity\Checks\SPF\SpfCheck;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\BindsFakeBlacklistDns;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class SecurityCheckContractTest extends TestCase
{
    use BindsFakeBlacklistDns;
    use RefreshDatabase;

    public function test_registered_checkers_implement_security_check_interface(): void
    {
        $registry = app(CheckRegistry::class);

        foreach (['spf', 'dmarc', 'blacklist'] as $key) {
            $this->assertContains($key, $registry->keys());
        }

        $this->assertInstanceOf(SecurityCheckInterface::class, app(SpfCheck::class));
        $this->assertInstanceOf(SecurityCheckInterface::class, app(DmarcCheck::class));
        $this->assertInstanceOf(SecurityCheckInterface::class, app(BlacklistCheck::class));
    }

    public function test_checker_keys_are_stable_and_unique(): void
    {
        $checks = [app(SpfCheck::class), app(DmarcCheck::class), app(BlacklistCheck::class)];
        $keys = array_map(fn (SecurityCheckInterface $check) => $check->key(), $checks);

        $this->assertSame(['spf', 'dmarc', 'blacklist'], $keys);
        $this->assertCount(count(array_unique($keys)), $keys);
    }

    public function test_spf_checker_returns_execution_result_with_native_artifacts(): void
    {
        $spfPayload = FixtureLoader::input('spf-configured');
        FixtureLoader::bindNativeSpfDns('example.test', $spfPayload['record']);

        $check = app(SpfCheck::class);
        $context = $this->makeContext();

        $execution = $check->run($context, null);

        $this->assertInstanceOf(CheckExecutionResultDTO::class, $execution);
        $this->assertSame('spf', $execution->result->key);
        $this->assertArrayHasKey(ScanArtifactKeys::NATIVE_SPF_RESULT, $execution->artifacts);
        $this->assertArrayHasKey(ScanArtifactKeys::LEGACY_SPF_RAW, $execution->artifacts);
        $this->assertSame('spf-native-v1', $execution->result->data['analysis']['version'] ?? null);
    }

    public function test_blacklist_checker_returns_execution_result_dto(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        FixtureLoader::bindMxFixtures($dnsPayload, 'example.test');
        $this->bindFakeBlacklistDns();

        $domain = Domain::factory()->create(['domain' => 'example.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $check = app(BlacklistCheck::class);
        $context = $this->makeContext($domain, $scan);
        $execution = $check->run($context, null);

        $this->assertInstanceOf(CheckExecutionResultDTO::class, $execution);
        $this->assertSame('blacklist', $execution->result->key);
        $this->assertArrayHasKey(ScanArtifactKeys::NATIVE_BLACKLIST_RESULT, $execution->artifacts);
        $this->assertArrayHasKey('analysis', $execution->result->data);
    }

    public function test_registry_rethrows_checker_failures_instead_of_false_pass(): void
    {
        $failing = new class implements SecurityCheckInterface {
            public function key(): string
            {
                return 'spf';
            }

            public function run(CheckContextDTO $context, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns): CheckExecutionResultDTO
            {
                throw new \RuntimeException('Controlled SPF checker failure');
            }
        };

        $registry = new CheckRegistry([$failing]);
        $context = $this->makeContext();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Controlled SPF checker failure');

        $registry->runEnabled($context, null, ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => false]));
    }

    private function makeContext(?Domain $domain = null, ?Scan $scan = null): CheckContextDTO
    {
        if ($domain === null) {
            $domain = Domain::factory()->create(['domain' => 'example.test']);
        }
        $scan ??= Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
        ]);

        return CheckContextDTO::fromExecution(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => true]),
        );
    }
}
