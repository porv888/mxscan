<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimNativeResult
{
    /**
     * @param list<array<string, mixed>> $selectors
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     * @param array<string, mixed> $selectorCoverage
     */
    public function __construct(
        public readonly string $state,
        public readonly string $protocolStatus,
        public readonly string $riskStatus,
        public readonly string $summary,
        public readonly string $signingDomain,
        public readonly bool $signingVerified,
        public readonly array $selectors,
        public readonly array $selectorCoverage,
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

    public function hasValidKey(): bool
    {
        foreach ($this->selectors as $selector) {
            if (($selector['record_status'] ?? '') === 'valid') {
                return true;
            }
        }

        return false;
    }
}
