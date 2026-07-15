<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt;

final class TlsRptNativeResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     * @param array<string, mixed> $record
     * @param array<string, mixed> $reporting
     */
    public function __construct(
        public readonly string $state,
        public readonly string $protocolStatus,
        public readonly string $riskStatus,
        public readonly string $summary,
        public readonly string $domain,
        public readonly string $recordHostname,
        public readonly string $evaluationCompleteness,
        public readonly ?string $rawRecord = null,
        public readonly array $record = [],
        public readonly array $reporting = [],
        public readonly array $errors = [],
        public readonly array $warnings = [],
        public readonly array $resolverDiagnostics = [],
        public readonly bool $hasMaterialWarnings = false,
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
