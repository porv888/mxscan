<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Compatibility;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;

final class SpfLegacyPayloadAdapter
{
    /**
     * @return array<string, mixed>
     */
    public function toResultJsonSpf(SpfNativeResult $native): array
    {
        $warnings = SpfLegacyWarningMapper::toLegacyCodes($native);
        $invalid = in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)
            || in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true);
        $error = null;

        if (in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)) {
            $error = 'SPF uses +all which allows any sender.';
        } elseif (in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true)) {
            $error = 'Multiple SPF records found; only one is allowed.';
        }

        $lookups = $native->lookupCount;
        $status = $lookups >= 10 ? 'error' : ($lookups >= 9 ? 'warning' : 'safe');
        if ($invalid || $native->state === 'fail') {
            $status = 'error';
        }

        return [
            'record' => $native->rawRecord,
            'lookups' => $lookups,
            'flattened' => $native->flattenedRecord,
            'status' => $status,
            'valid' => !$invalid && $native->rawRecord !== null && $native->state !== 'fail',
            'error' => $error,
            'warnings' => $warnings,
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
}
