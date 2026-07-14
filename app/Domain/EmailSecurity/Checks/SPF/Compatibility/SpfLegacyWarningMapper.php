<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Compatibility;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;

final class SpfLegacyWarningMapper
{
    private const MAP = [
        'DEPRECATED_PTR' => SpfResolver::WARNING_PTR_USED,
        'PLUS_ALL' => SpfResolver::WARNING_PLUS_ALL,
        'INCLUDE_NXDOMAIN' => SpfResolver::WARNING_INCLUDE_NXDOMAIN,
        'INCLUDE_NONE_PERMERROR' => SpfResolver::WARNING_INCLUDE_NXDOMAIN,
        'REDIRECT_NONE_PERMERROR' => SpfResolver::WARNING_INCLUDE_NXDOMAIN,
        'LOOP_DETECTED' => SpfResolver::WARNING_LOOP_DETECTED,
        'REDIRECT_CHAIN_LONG' => SpfResolver::WARNING_REDIRECT_CHAIN_LONG,
        'UNKNOWN_MECHANISM' => SpfResolver::WARNING_UNKNOWN_MECH,
        'LOOKUP_LIMIT' => SpfResolver::WARNING_LOOKUP_LIMIT,
        'MULTIPLE_SPF_RECORDS' => SpfResolver::WARNING_MULTIPLE_SPF,
        'UNSUPPORTED_SPF_MACRO' => SpfResolver::WARNING_UNSUPPORTED_MACRO,
        'DNS_TEMPERROR' => SpfResolver::WARNING_TIMEOUT,
        'VOID_LOOKUP_LIMIT' => SpfResolver::WARNING_LOOKUP_LIMIT,
    ];

    /**
     * @return list<string>
     */
    public static function toLegacyCodes(SpfNativeResult $native): array
    {
        $codes = [];

        if ($native->state === 'missing') {
            $codes[] = SpfResolver::WARNING_NO_SPF;
        }

        foreach (array_merge($native->errors, $native->warnings) as $item) {
            $code = $item['code'] ?? '';
            if (isset(self::MAP[$code])) {
                $codes[] = self::MAP[$code];
            }
        }

        return array_values(array_unique($codes));
    }
}
