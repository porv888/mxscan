<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfNativeResult
{
    /**
     * @param list<array<string, mixed>> $parsedTerms
     * @param list<array<string, mixed>> $lookupPaths
     * @param list<array<string, mixed>> $recursiveDependencies
     * @param list<string> $resolvedIps
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     * @param array<string, mixed> $discovery
     */
    public function __construct(
        public readonly string $state,
        public readonly string $summary,
        public readonly ?string $rawRecord,
        public readonly ?string $normalizedRecord,
        public readonly array $parsedTerms,
        public readonly ?array $terminalPolicy,
        public readonly int $lookupCount,
        public readonly int $lookupLimit,
        public readonly int $lookupsRemaining,
        public readonly int $voidLookupCount,
        public readonly array $lookupPaths,
        public readonly array $recursiveDependencies,
        public readonly array $resolvedIps,
        public readonly ?string $flattenedRecord,
        public readonly array $errors,
        public readonly array $warnings,
        public readonly array $resolverDiagnostics,
        public readonly array $discovery,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'summary' => $this->summary,
            'raw_record' => $this->rawRecord,
            'normalized_record' => $this->normalizedRecord,
            'parsed_terms' => $this->parsedTerms,
            'terminal_policy' => $this->terminalPolicy,
            'lookup_count' => $this->lookupCount,
            'lookup_limit' => $this->lookupLimit,
            'lookups_remaining' => $this->lookupsRemaining,
            'void_lookup_count' => $this->voidLookupCount,
            'lookup_paths' => $this->lookupPaths,
            'recursive_dependencies' => $this->recursiveDependencies,
            'resolved_ips' => $this->resolvedIps,
            'flattened_record' => $this->flattenedRecord,
            'errors' => $this->errors,
            'warnings' => $this->warnings,
            'resolver_diagnostics' => $this->resolverDiagnostics,
            'discovery' => $this->discovery,
        ];
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
