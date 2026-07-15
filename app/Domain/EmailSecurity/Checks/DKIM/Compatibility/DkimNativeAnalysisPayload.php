<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Compatibility;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;

final class DkimNativeAnalysisPayload
{
    public const VERSION = 'dkim-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(DkimNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'signing_domain' => $native->signingDomain,
            'signing_verified' => $native->signingVerified,
            'selector_coverage' => $native->selectorCoverage,
            'selectors' => $native->selectors,
            'errors' => $this->sanitizeMessages($native->errors),
            'warnings' => $this->sanitizeMessages($native->warnings),
            'resolver_diagnostics' => $native->resolverDiagnostics,
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
}
