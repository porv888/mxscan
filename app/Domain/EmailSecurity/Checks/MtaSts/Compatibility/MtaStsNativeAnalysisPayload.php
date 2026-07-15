<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Compatibility;

use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates;

final class MtaStsNativeAnalysisPayload
{
    public const VERSION = 'mta-sts-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(MtaStsNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'domain' => $native->domain,
            'dns_indicator' => $native->dnsIndicator,
            'policy_fetch' => $native->policyFetch,
            'policy_host_tls' => $native->policyHostTls,
            'policy' => $native->policy,
            'mx_validation' => $native->mxValidation,
            'evaluation_completeness' => $native->evaluationCompleteness,
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
