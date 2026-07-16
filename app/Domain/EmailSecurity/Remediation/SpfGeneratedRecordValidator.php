<?php

namespace App\Domain\EmailSecurity\Remediation;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidator;

final class SpfGeneratedRecordValidator
{
    public function __construct(
        private SpfParser $parser,
        private SpfValidator $validator,
        private SpfDnsDependencyResolver $dns,
    ) {
    }

    /**
     * @return array{errors: list<array{code: string, message: string}>, warnings: list<array{code: string, message: string}>, lookup_count: int}
     */
    public function validate(string $domain, string $record, int $existingSpfCount = 0): array
    {
        $terms = $this->parser->parse($record, $domain);
        $result = $this->validator->validate(
            $terms,
            new SpfDiscoveryResult(
                domain: $domain,
                source: 'generated',
                record: $record,
                multipleRecords: $existingSpfCount > 1,
            ),
            $record,
        );

        $errors = array_map(
            fn (array $item) => ['code' => (string) ($item['code'] ?? ''), 'message' => (string) ($item['message'] ?? '')],
            $result->errors,
        );
        $warnings = array_map(
            fn (array $item) => ['code' => (string) ($item['code'] ?? ''), 'message' => (string) ($item['message'] ?? '')],
            $result->warnings,
        );

        $lookupCount = 0;
        $visited = [];
        foreach ($terms as $term) {
            if ($term->name !== 'include' || !$term->argument) {
                continue;
            }

            $lookupCount++;
            $this->validateInclude($term->argument, $lookupCount, $visited, $errors);
        }

        if ($lookupCount > 10) {
            $errors[] = ['code' => 'LOOKUP_LIMIT_EXCEEDED', 'message' => 'SPF requires more than 10 DNS lookups.'];
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'lookup_count' => $lookupCount,
        ];
    }

    /**
     * @param array<string, bool> $visited
     * @param list<array{code: string, message: string}> $errors
     */
    private function validateInclude(string $domain, int &$lookupCount, array &$visited, array &$errors): void
    {
        $domain = strtolower(rtrim(trim($domain), '.'));
        if (isset($visited[$domain]) || $lookupCount > 10) {
            return;
        }
        $visited[$domain] = true;

        $result = $this->dns->txt($domain);
        if (!$result->success || $result->records === []) {
            $errors[] = ['code' => 'INCLUDE_NOT_RESOLVED', 'message' => "SPF include {$domain} did not resolve."];
            return;
        }

        $spf = collect($result->records)
            ->first(fn ($value) => is_string($value) && str_starts_with(strtolower(trim($value)), 'v=spf1'));
        if (!is_string($spf)) {
            $errors[] = ['code' => 'INCLUDE_HAS_NO_SPF', 'message' => "SPF include {$domain} has no SPF record."];
            return;
        }

        foreach ($this->parser->parse($spf, $domain) as $term) {
            if (in_array($term->name, ['include', 'a', 'mx', 'exists', 'redirect'], true)) {
                $lookupCount++;
            }
            if ($term->name === 'include' && $term->argument) {
                $this->validateInclude($term->argument, $lookupCount, $visited, $errors);
            }
        }
    }
}
