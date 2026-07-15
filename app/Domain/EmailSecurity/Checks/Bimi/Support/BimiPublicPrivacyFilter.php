<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Support;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiProtocolStatus;

final class BimiPublicPrivacyFilter
{
    /**
     * @param array<string, mixed>|null $analysis
     * @return array<string, mixed>|null
     */
    public function filter(?array $analysis): ?array
    {
        if ($analysis === null) {
            return null;
        }

        $indicatorStatus = (string) ($analysis['indicator']['status'] ?? 'absent');
        $protocolStatus = (string) ($analysis['protocol_status'] ?? BimiProtocolStatus::NONE);

        return [
            'summary' => (string) ($analysis['summary'] ?? 'BIMI readiness information is unavailable.'),
            'protocol_status' => $protocolStatus,
            'readiness_status' => (string) ($analysis['readiness_status'] ?? 'unknown'),
            'record_hostname' => is_string($analysis['record_hostname'] ?? null)
                ? $analysis['record_hostname']
                : (is_string($analysis['selector']['record_hostname'] ?? null) ? $analysis['selector']['record_hostname'] : null),
            'logo_validation_status' => $this->logoValidationStatus($indicatorStatus, $protocolStatus),
            'dmarc_core_eligible' => is_bool($analysis['dmarc_eligibility']['core_eligible'] ?? null)
                ? $analysis['dmarc_eligibility']['core_eligible']
                : null,
            'mark_certificate_status' => is_string($analysis['authority_evidence']['status'] ?? null)
                ? $analysis['authority_evidence']['status']
                : null,
            'mark_certificate_type' => is_string($analysis['authority_evidence']['type'] ?? null)
                ? $analysis['authority_evidence']['type']
                : null,
            'declined' => $protocolStatus === BimiProtocolStatus::DECLINED,
        ];
    }

    /**
     * @param array<string, mixed>|null $bimiInfo
     * @return array<string, mixed>|null
     */
    public function filterFromResult(?array $bimiInfo, ?array $legacyDnsRecord = null): ?array
    {
        $analysis = BimiAnalysisReader::analysis($bimiInfo)
            ?? BimiAnalysisReader::fromLegacyDnsRecord($legacyDnsRecord, $bimiInfo);

        return $this->filter($analysis);
    }

    private function logoValidationStatus(string $indicatorStatus, string $protocolStatus): string
    {
        if ($protocolStatus === BimiProtocolStatus::NONE) {
            return 'absent';
        }

        if ($protocolStatus === BimiProtocolStatus::DECLINED) {
            return 'not_checked';
        }

        return match ($indicatorStatus) {
            'valid' => 'valid',
            'invalid' => 'invalid',
            'unavailable' => 'unavailable',
            'not_checked' => 'not_checked',
            default => 'absent',
        };
    }
}
