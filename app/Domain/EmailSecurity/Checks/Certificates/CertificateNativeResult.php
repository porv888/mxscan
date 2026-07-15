<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

final class CertificateNativeResult
{
    /**
     * @param array<string, int> $counts
     * @param list<array<string, mixed>> $endpoints
     * @param array<string, mixed>|null $earliestExpiry
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly string $state,
        public readonly string $analysisStatus,
        public readonly string $riskStatus,
        public readonly string $summary,
        public readonly string $domain,
        public readonly string $evaluationCompleteness,
        public readonly array $counts,
        public readonly array $endpoints,
        public readonly ?array $earliestExpiry = null,
        public readonly array $errors = [],
        public readonly array $warnings = [],
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
