<?php

namespace App\Domain\EmailSecurity\Support;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;

final class ScoringInputFactory
{
    public function from(
        NormalizedScanResultDTO $normalized,
        ?SpfNativeResult $nativeSpf = null,
        ?DmarcNativeResult $nativeDmarc = null,
        ?DkimNativeResult $nativeDkim = null,
        ?MtaStsNativeResult $nativeMtaSts = null,
        ?TlsRptNativeResult $nativeTlsRpt = null,
        ?MxNativeResult $nativeMx = null,
        ?CertificateNativeResult $nativeCertificate = null,
        ?BimiNativeResult $nativeBimi = null,
    ): ScoringInputDTO {
        $legacy = $normalized->legacyDnsMetadata;
        $useNativeSpf = $nativeSpf !== null;
        $useNativeDmarc = $nativeDmarc !== null;
        $useNativeDkim = $nativeDkim !== null;
        $useNativeMtaSts = $nativeMtaSts !== null;
        $useNativeTlsRpt = $nativeTlsRpt !== null;
        $useNativeMx = $nativeMx !== null;
        $scoreModelVersion = $this->buildScoreModelVersion(
            $useNativeSpf,
            $useNativeDmarc,
            $useNativeDkim,
            $useNativeMtaSts,
            $useNativeTlsRpt,
            $useNativeMx,
        );

        return new ScoringInputDTO(
            normalized: $normalized,
            scoreBreakdown: $legacy['score_breakdown'] ?? [],
            scoreModelVersion: $scoreModelVersion,
            compatibilityMeta: [
                'authoritative_score' => $legacy['score'] ?? null,
                'score_source' => $useNativeSpf || $useNativeDmarc || $useNativeDkim || $useNativeMtaSts || $useNativeTlsRpt || $useNativeMx
                    ? 'native_score_rules'
                    : 'legacy_dns_payload',
            ],
            nativeSpfResult: $nativeSpf,
            nativeDmarcResult: $nativeDmarc,
            nativeDkimResult: $nativeDkim,
            nativeMtaStsResult: $nativeMtaSts,
            nativeTlsRptResult: $nativeTlsRpt,
            nativeMxResult: $nativeMx,
            nativeCertificateResult: $nativeCertificate,
            nativeBimiResult: $nativeBimi,
        );
    }

    private function buildScoreModelVersion(
        bool $useNativeSpf,
        bool $useNativeDmarc,
        bool $useNativeDkim,
        bool $useNativeMtaSts,
        bool $useNativeTlsRpt,
        bool $useNativeMx,
    ): string {
        $parts = [];
        if ($useNativeSpf) {
            $parts[] = 'spf-v2';
        }
        if ($useNativeDmarc) {
            $parts[] = 'dmarc-v1';
        }
        if ($useNativeDkim) {
            $parts[] = 'dkim-v1';
        }
        if ($useNativeMtaSts) {
            $parts[] = 'mta-sts-v1';
        }
        if ($useNativeTlsRpt) {
            $parts[] = 'tls-rpt-v1';
        }
        if ($useNativeMx) {
            $parts[] = 'mx-v1';
        }

        return $parts !== [] ? implode('+', $parts) : 'legacy-v1';
    }
}
