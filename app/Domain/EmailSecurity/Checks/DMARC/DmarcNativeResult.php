<?php

namespace App\Domain\EmailSecurity\Checks\DMARC;

final class DmarcNativeResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     * @param array<string, mixed> $discovery
     * @param array<string, mixed> $policy
     * @param array{dkim: string, spf: string} $alignment
     * @param array<string, mixed> $aggregateReporting
     * @param array<string, mixed> $failureReporting
     * @param array<string, mixed> $externalAuthorization
     */
    public function __construct(
        public readonly string $state,
        public readonly string $protocolStatus,
        public readonly string $riskStatus,
        public readonly string $summary,
        public readonly ?string $rawRecord,
        public readonly ?string $recordDomain,
        public readonly ?string $policyDomain,
        public readonly string $policySource,
        public readonly ?string $organizationalDomain,
        public readonly array $discovery,
        public readonly array $policy,
        public readonly array $alignment,
        public readonly array $aggregateReporting,
        public readonly array $failureReporting,
        public readonly array $externalAuthorization,
        public readonly array $errors,
        public readonly array $warnings,
        public readonly array $resolverDiagnostics,
    ) {
    }

    /**
     * @return list<string>
     */
    public function messageSummaries(): array
    {
        $messages = [$this->summary];
        foreach ($this->warnings as $warning) {
            $messages[] = $warning['message'] ?? '';
        }

        return array_values(array_filter($messages));
    }
}
