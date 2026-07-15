<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Compatibility;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;

final class DmarcNativeAnalysisPayload
{
    public const VERSION = 'dmarc-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(DmarcNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'record' => $native->rawRecord,
            'record_domain' => $native->recordDomain,
            'policy_domain' => $native->policyDomain,
            'policy_source' => $native->policySource,
            'organizational_domain' => $native->organizationalDomain,
            'discovery' => $native->discovery,
            'policy' => $native->policy,
            'alignment' => $native->alignment,
            'alignment_verification' => DmarcAlignmentVerification::NOT_VERIFIED,
            'aggregate_reporting' => $native->aggregateReporting,
            'failure_reporting' => $native->failureReporting,
            'external_authorization' => $native->externalAuthorization,
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
