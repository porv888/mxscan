<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Compatibility;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;

final class CertificateNativeAnalysisPayload
{
    public const VERSION = 'certificates-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(CertificateNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'analysis_status' => $native->analysisStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'domain' => $native->domain,
            'counts' => $native->counts,
            'endpoints' => $native->endpoints,
            'earliest_expiry' => $native->earliestExpiry,
            'evaluation_completeness' => $native->evaluationCompleteness,
            'errors' => $this->sanitizeMessages($native->errors),
            'warnings' => $this->sanitizeMessages($native->warnings),
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
