<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Compatibility;

use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;

final class MxNativeAnalysisPayload
{
    public const VERSION = 'mx-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(MxNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'domain' => $native->domain,
            'service_mode' => $native->serviceMode,
            'dns_status' => $native->dnsStatus,
            'records_total' => $native->recordsTotal,
            'usable_targets' => $native->usableTargets,
            'invalid_targets' => $native->invalidTargets,
            'null_mx' => $native->nullMx,
            'implicit_fallback' => $native->implicitFallback,
            'preference_groups' => $native->preferenceGroups,
            'targets' => $native->targets,
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
