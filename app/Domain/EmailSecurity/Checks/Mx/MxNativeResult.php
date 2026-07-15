<?php

namespace App\Domain\EmailSecurity\Checks\Mx;

final class MxNativeResult
{
    /**
     * @param list<array<string, mixed>> $targets
     * @param list<array{preference: int, targets: list<string>}> $preferenceGroups
     * @param array<string, mixed> $nullMx
     * @param array<string, mixed> $implicitFallback
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    public function __construct(
        public readonly string $state,
        public readonly string $protocolStatus,
        public readonly string $riskStatus,
        public readonly string $summary,
        public readonly string $domain,
        public readonly string $serviceMode,
        public readonly string $dnsStatus,
        public readonly int $recordsTotal,
        public readonly int $usableTargets,
        public readonly int $invalidTargets,
        public readonly array $nullMx,
        public readonly array $implicitFallback,
        public readonly array $preferenceGroups,
        public readonly array $targets,
        public readonly string $evaluationCompleteness,
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
