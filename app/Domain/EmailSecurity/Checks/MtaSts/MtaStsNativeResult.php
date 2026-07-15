<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts;

final class MtaStsNativeResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     * @param array<string, mixed> $dnsIndicator
     * @param array<string, mixed> $policyFetch
     * @param array<string, mixed> $policyHostTls
     * @param array<string, mixed> $policy
     * @param list<array<string, mixed>> $mxValidation
     */
    public function __construct(
        public readonly string $state,
        public readonly string $protocolStatus,
        public readonly string $riskStatus,
        public readonly string $summary,
        public readonly string $domain,
        public readonly string $evaluationCompleteness,
        public readonly ?string $rawIndicator = null,
        public readonly array $dnsIndicator = [],
        public readonly array $policyFetch = [],
        public readonly array $policyHostTls = [],
        public readonly array $policy = [],
        public readonly array $mxValidation = [],
        public readonly array $errors = [],
        public readonly array $warnings = [],
        public readonly array $resolverDiagnostics = [],
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
