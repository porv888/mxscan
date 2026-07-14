<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use Tests\TestCase;

class CheckRegistryArchitectureTest extends TestCase
{
    public function test_registry_source_has_no_protocol_specific_branches(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/CheckRegistry.php'));

        $this->assertStringNotContainsString('instanceof', $source);
        $this->assertStringNotContainsString('runWithRaw', $source);
        $this->assertStringNotContainsString('SpfAnalysisCheck', $source);
        $this->assertStringNotContainsString('legacy_spf_raw', $source);
    }

    public function test_registry_merges_artifacts_without_protocol_knowledge(): void
    {
        $checkA = new class implements SecurityCheckInterface {
            public function key(): string
            {
                return 'spf';
            }

            public function run(CheckContextDTO $context, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns): CheckExecutionResultDTO
            {
                return new CheckExecutionResultDTO(
                    result: new CheckResultDTO('spf', 'safe', ['status' => 'safe']),
                    artifacts: ['artifact_a' => 'value-a'],
                );
            }
        };

        $checkB = new class implements SecurityCheckInterface {
            public function key(): string
            {
                return 'blacklist';
            }

            public function run(CheckContextDTO $context, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns): CheckExecutionResultDTO
            {
                return new CheckExecutionResultDTO(
                    result: new CheckResultDTO('blacklist', 'clean', ['is_clean' => true]),
                    artifacts: ['artifact_b' => 'value-b'],
                );
            }
        };

        $registry = new CheckRegistry([$checkA, $checkB]);
        $context = new CheckContextDTO(
            domainName: 'example.test',
            domainId: 1,
            scanId: '00000000-0000-4000-8000-000000000001',
            scanType: 'full',
            enabledServices: ['dns' => true, 'spf' => true, 'blacklist' => true],
            environment: 'testing',
            correlationId: '00000000-0000-4000-8000-000000000001',
            executedAt: now()->toIso8601String(),
        );

        $collection = $registry->runEnabled(
            $context,
            null,
            ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => true]),
        );

        $this->assertSame(['artifact_a' => 'value-a', 'artifact_b' => 'value-b'], $collection->artifacts);
        $this->assertArrayHasKey('spf', $collection->results);
        $this->assertArrayHasKey('blacklist', $collection->results);
    }

    public function test_registry_rejects_duplicate_artifact_keys(): void
    {
        $checkA = new class implements SecurityCheckInterface {
            public function key(): string
            {
                return 'spf';
            }

            public function run(CheckContextDTO $context, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns): CheckExecutionResultDTO
            {
                return new CheckExecutionResultDTO(
                    result: new CheckResultDTO('spf', 'safe'),
                    artifacts: [ScanArtifactKeys::LEGACY_SPF_RAW => 'first'],
                );
            }
        };

        $checkB = new class implements SecurityCheckInterface {
            public function key(): string
            {
                return 'blacklist';
            }

            public function run(CheckContextDTO $context, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns): CheckExecutionResultDTO
            {
                return new CheckExecutionResultDTO(
                    result: new CheckResultDTO('blacklist', 'clean'),
                    artifacts: [ScanArtifactKeys::LEGACY_SPF_RAW => 'second'],
                );
            }
        };

        $registry = new CheckRegistry([$checkA, $checkB]);
        $context = new CheckContextDTO(
            domainName: 'example.test',
            domainId: 1,
            scanId: '00000000-0000-4000-8000-000000000001',
            scanType: 'full',
            enabledServices: ['dns' => true, 'spf' => true, 'blacklist' => true],
            environment: 'testing',
            correlationId: '00000000-0000-4000-8000-000000000001',
            executedAt: now()->toIso8601String(),
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Duplicate artifact key registered: ' . ScanArtifactKeys::LEGACY_SPF_RAW);

        $registry->runEnabled(
            $context,
            null,
            ScanOptionsDTO::fromArray(['dns' => false, 'spf' => true, 'blacklist' => true]),
        );
    }
}
