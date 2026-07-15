<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Compatibility;

use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;

final class TlsRptNativeAnalysisPayload
{
    public const VERSION = 'tls-rpt-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(TlsRptNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'domain' => $native->domain,
            'record_hostname' => $native->recordHostname,
            'record' => $native->record,
            'reporting' => $native->reporting,
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
