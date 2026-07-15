<?php

namespace App\Domain\EmailSecurity\DTO;

use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;

final class ScoringInputDTO
{
    /**
     * @param list<array<string, mixed>> $scoreBreakdown
     * @param array<string, mixed> $compatibilityMeta
     */
    public function __construct(
        public readonly NormalizedScanResultDTO $normalized,
        public readonly array $scoreBreakdown,
        public readonly string $scoreModelVersion = 'legacy-v1',
        public readonly array $compatibilityMeta = [],
        public readonly ?SpfNativeResult $nativeSpfResult = null,
        public readonly ?DmarcNativeResult $nativeDmarcResult = null,
        public readonly ?DkimNativeResult $nativeDkimResult = null,
        public readonly ?MtaStsNativeResult $nativeMtaStsResult = null,
        public readonly ?TlsRptNativeResult $nativeTlsRptResult = null,
        public readonly ?MxNativeResult $nativeMxResult = null,
        public readonly ?CertificateNativeResult $nativeCertificateResult = null,
        public readonly ?BimiNativeResult $nativeBimiResult = null,
    ) {
    }
}
