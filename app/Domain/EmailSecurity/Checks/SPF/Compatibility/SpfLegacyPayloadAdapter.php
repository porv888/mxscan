<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Compatibility;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;

final class SpfLegacyPayloadAdapter
{
    public function __construct(
        private SpfNativeAnalysisPayload $analysisPayload = new SpfNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonSpf(SpfNativeResult $native): array
    {
        $warnings = SpfLegacyWarningMapper::toLegacyCodes($native);
        $invalid = in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)
            || in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true)
            || $native->protocolStatus === SpfProtocolStatus::PERMERROR;
        $error = null;

        if (in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)) {
            $error = 'SPF uses +all which allows any sender.';
        } elseif (in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true)) {
            $error = 'Multiple SPF records found; only one is allowed.';
        } elseif ($native->protocolStatus === SpfProtocolStatus::PERMERROR) {
            $error = $native->summary;
        }

        $lookups = $native->lookupCount;
        $status = $this->legacyStatus($native, $lookups, $invalid);
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'record' => $native->rawRecord,
            'lookups' => $lookups,
            'flattened' => $native->flattenedRecord,
            'status' => $status,
            'valid' => $this->isValid($native),
            'error' => $error,
            'warnings' => $warnings,
            'protocol_status' => $analysis['protocol_status'],
            'risk_status' => $analysis['risk_status'],
            'ui_state' => $analysis['state'],
            'summary' => $analysis['summary'],
            'analysis' => $analysis,
        ];
    }

    public function toSpfResultDto(SpfNativeResult $native): SpfResultDTO
    {
        return new SpfResultDTO(
            currentRecord: $native->rawRecord,
            lookupsUsed: $native->lookupCount,
            flattenedSpf: $native->flattenedRecord,
            warnings: SpfLegacyWarningMapper::toLegacyCodes($native),
            resolvedIps: $native->resolvedIps,
        );
    }

    private function legacyStatus(SpfNativeResult $native, int $lookups, bool $invalid): string
    {
        if ($invalid || $native->state === 'fail') {
            return 'error';
        }

        if ($native->protocolStatus === SpfProtocolStatus::TEMPERROR
            || $native->protocolStatus === SpfProtocolStatus::PARTIALLY_EVALUATED) {
            return $lookups >= 7 ? 'warning' : 'safe';
        }

        if ($lookups > 10) {
            return 'error';
        }

        if ($lookups >= 7) {
            return 'warning';
        }

        return 'safe';
    }

    private function isValid(SpfNativeResult $native): bool
    {
        if ($native->rawRecord === null) {
            return false;
        }

        return !in_array($native->protocolStatus, [
            SpfProtocolStatus::NONE,
            SpfProtocolStatus::PERMERROR,
        ], true);
    }
}
