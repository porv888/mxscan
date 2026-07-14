<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Compatibility;

use App\Domain\EmailSecurity\Checks\SPF\SpfEvaluationCompleteness;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;

final class SpfNativeAnalysisPayload
{
    public const VERSION = 'spf-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(SpfNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'terminal_policy' => $native->terminalPolicy,
            'lookup_count' => $native->lookupCount,
            'lookup_limit' => $native->lookupLimit,
            'lookups_remaining' => $native->lookupsRemaining,
            'void_lookup_count' => $native->voidLookupCount,
            'evaluation_completeness' => SpfEvaluationCompleteness::derive($native->protocolStatus),
            'errors' => $this->sanitizeMessages($native->errors),
            'warnings' => $this->sanitizeMessages($native->warnings),
            'dependencies' => $this->sanitizeDependencies($native->recursiveDependencies),
        ];
    }

    /**
     * @param list<array{code?: string, message?: string}> $items
     * @return list<array{code: string, message: string}>
     */
    private function sanitizeMessages(array $items): array
    {
        return array_values(array_map(
            fn (array $item) => [
                'code' => (string) ($item['code'] ?? ''),
                'message' => (string) ($item['message'] ?? ''),
            ],
            $items,
        ));
    }

    /**
     * @param list<array<string, mixed>> $dependencies
     * @return list<array{mechanism: string, domain: string}>
     */
    private function sanitizeDependencies(array $dependencies): array
    {
        $sanitized = [];
        foreach ($dependencies as $dependency) {
            $mechanism = (string) ($dependency['mechanism'] ?? '');
            $domain = (string) ($dependency['domain'] ?? '');
            if ($mechanism === '' || $domain === '') {
                continue;
            }
            $sanitized[] = [
                'mechanism' => $mechanism,
                'domain' => $domain,
            ];
        }

        return $sanitized;
    }
}
