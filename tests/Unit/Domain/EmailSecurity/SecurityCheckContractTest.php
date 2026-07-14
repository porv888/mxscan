<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Checks\BlacklistCheck;
use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\Checks\SpfAnalysisCheck;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\BlacklistChecker;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class SecurityCheckContractTest extends TestCase
{
    use RefreshDatabase;

    public function test_registered_checkers_implement_security_check_interface(): void
    {
        $registry = app(CheckRegistry::class);

        foreach (['spf', 'blacklist'] as $key) {
            $this->assertContains($key, $registry->keys());
        }

        $this->assertInstanceOf(SecurityCheckInterface::class, app(SpfAnalysisCheck::class));
        $this->assertInstanceOf(SecurityCheckInterface::class, app(BlacklistCheck::class));
    }

    public function test_checker_keys_are_stable_and_unique(): void
    {
        $checks = [app(SpfAnalysisCheck::class), app(BlacklistCheck::class)];
        $keys = array_map(fn (SecurityCheckInterface $check) => $check->key(), $checks);

        $this->assertSame(['spf', 'blacklist'], $keys);
        $this->assertCount(count(array_unique($keys)), $keys);
    }

    public function test_spf_checker_returns_execution_result_with_legacy_artifact(): void
    {
        $spfPayload = FixtureLoader::input('spf-configured');
        $raw = new SpfResultDTO(
            currentRecord: $spfPayload['record'],
            lookupsUsed: $spfPayload['lookups'],
            flattenedSpf: $spfPayload['flattened'],
            warnings: [],
            resolvedIps: [],
        );
        $resolver = Mockery::mock(SpfResolver::class);
        $resolver->shouldReceive('resolve')
            ->once()
            ->with('example.test')
            ->andReturn($raw);

        $check = new SpfAnalysisCheck($resolver);
        $context = $this->makeContext();

        $execution = $check->run($context, null);

        $this->assertInstanceOf(CheckExecutionResultDTO::class, $execution);
        $this->assertSame('spf', $execution->result->key);
        $this->assertSame('safe', $execution->result->status);
        $this->assertArrayHasKey(ScanArtifactKeys::LEGACY_SPF_RAW, $execution->artifacts);
        $this->assertSame($raw, $execution->artifacts[ScanArtifactKeys::LEGACY_SPF_RAW]);
    }

    public function test_blacklist_checker_returns_execution_result_dto(): void
    {
        $summary = FixtureLoader::input('blacklist-clean');
        $domain = Domain::factory()->create(['domain' => 'example.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);

        $checker = Mockery::mock(BlacklistChecker::class);
        $checker->shouldReceive('checkDomain')->once()->with(Mockery::type(Scan::class), 'example.test');
        $checker->shouldReceive('getScanSummary')->once()->with(Mockery::type(Scan::class))->andReturn($summary);

        $check = new BlacklistCheck($checker);
        $context = $this->makeContext($domain, $scan);
        $execution = $check->run($context, null);

        $this->assertInstanceOf(CheckExecutionResultDTO::class, $execution);
        $this->assertSame('blacklist', $execution->result->key);
        $this->assertSame('clean', $execution->result->status);
        $this->assertSame([], $execution->artifacts);
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
        $domain ??= new Domain(['domain' => 'example.test']);
        $domain->id ??= 1;
        $scan ??= new Scan(['id' => '00000000-0000-4000-8000-000000000001']);

        return CheckContextDTO::fromExecution(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => true]),
        );
    }
}
