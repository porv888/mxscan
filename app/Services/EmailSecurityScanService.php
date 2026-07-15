<?php

namespace App\Services;

use App\Domain\EmailSecurity\Checks\BundledDnsChecksAdapter;
use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\Contracts\DnsCollectorInterface;
use App\Domain\EmailSecurity\Contracts\RecommendationEngineInterface;
use App\Domain\EmailSecurity\Contracts\ScoreCalculatorInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Domain\EmailSecurity\Support\ScanResultAssembler;
use App\Domain\EmailSecurity\Support\ScoringInputFactory;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Support\Facades\Log;

/**
 * Single orchestration façade for email security domain scans.
 */
final class EmailSecurityScanService
{
    public function __construct(
        private DnsCollectorInterface $dnsCollector,
        private CheckRegistry $checkRegistry,
        private BundledDnsChecksAdapter $bundledDnsChecksAdapter,
        private ScanResultAssembler $resultAssembler,
        private ScoringInputFactory $scoringInputFactory,
        private ScoreCalculatorInterface $scoreCalculator,
        private RecommendationEngineInterface $recommendationEngine,
    ) {
    }

    /**
     * @param callable(string, array<string, mixed>): void|null $onProgress
     */
    public function execute(
        Domain $domain,
        Scan $scan,
        ScanOptionsDTO $options,
        float $startTime,
        ?callable $onProgress = null,
    ): ScanExecutionResultDTO {
        $context = CheckContextDTO::fromExecution($domain, $scan, $options);
        $dns = null;
        $bundledResults = [];
        $spfRawResult = null;

        if ($options->dns) {
            Log::info('Running DNS scan', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $dns = $this->dnsCollector->collect($domain->domain);
            $bundledResults = $this->bundledDnsChecksAdapter->adapt($dns);
            $onProgress && $onProgress('dns_done', $dns->legacyDnsPayload);
        }

        $nativeCollection = $this->checkRegistry->runEnabled($context, $dns, $options);
        $nativeResults = $nativeCollection->results;
        $spfRawResult = ScanPayloadBuilder::legacySpfRawFromArtifacts($nativeCollection->artifacts);

        if ($options->spf && isset($nativeResults['spf'])) {
            Log::info('Running SPF analysis', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('spf_done', $nativeResults['spf']->data ?? []);
        }

        if ($options->dns && isset($nativeResults['dmarc'])) {
            Log::info('Running DMARC analysis', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('dmarc_done', $nativeResults['dmarc']->data ?? []);
        }

        if (($options->dns || $options->dkim) && isset($nativeResults['dkim'])) {
            Log::info('Running DKIM analysis', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('dkim_done', $nativeResults['dkim']->data ?? []);
        }

        if ($options->dns && isset($nativeResults['mx'])) {
            Log::info('Running MX analysis', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('mx_done', $nativeResults['mx']->data ?? []);
        }

        if ($options->dns && isset($nativeResults['mtasts'])) {
            Log::info('Running MTA-STS analysis', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('mtasts_done', $nativeResults['mtasts']->data ?? []);
        }

        if ($options->dns && isset($nativeResults['tlsrpt'])) {
            Log::info('Running TLS-RPT analysis', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('tlsrpt_done', $nativeResults['tlsrpt']->data ?? []);
        }

        if ($options->dns && isset($nativeResults['bimi'])) {
            Log::info('Running BIMI analysis', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('bimi_done', $nativeResults['bimi']->data ?? []);
        }

        if ($options->blacklist && isset($nativeResults['blacklist'])) {
            Log::info('Running blacklist check', ['domain' => $domain->domain, 'scan_id' => $scan->id]);
            $onProgress && $onProgress('blacklist_done', $nativeResults['blacklist']->data ?? []);
        }

        $normalized = $this->resultAssembler->assembleNormalized($context, $dns, $bundledResults, $nativeResults);
        $scanResult = $this->resultAssembler->toScanResultDTO($normalized);
        $nativeSpf = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_SPF_RESULT] ?? null;
        if (!$nativeSpf instanceof SpfNativeResult) {
            $nativeSpf = null;
        }
        $nativeDmarc = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_DMARC_RESULT] ?? null;
        if (!$nativeDmarc instanceof DmarcNativeResult) {
            $nativeDmarc = null;
        }
        $nativeDkim = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_DKIM_RESULT] ?? null;
        if (!$nativeDkim instanceof DkimNativeResult) {
            $nativeDkim = null;
        }
        $nativeMtaSts = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_MTA_STS_RESULT] ?? null;
        if (!$nativeMtaSts instanceof MtaStsNativeResult) {
            $nativeMtaSts = null;
        }
        $nativeTlsRpt = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_TLS_RPT_RESULT] ?? null;
        if (!$nativeTlsRpt instanceof TlsRptNativeResult) {
            $nativeTlsRpt = null;
        }
        $nativeMx = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_MX_RESULT] ?? null;
        if (!$nativeMx instanceof MxNativeResult) {
            $nativeMx = null;
        }
        $nativeCertificate = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_CERTIFICATE_RESULT] ?? null;
        if (!$nativeCertificate instanceof CertificateNativeResult) {
            $nativeCertificate = null;
        }
        $nativeBimi = $nativeCollection->artifacts[ScanArtifactKeys::NATIVE_BIMI_RESULT] ?? null;
        if (!$nativeBimi instanceof BimiNativeResult) {
            $nativeBimi = null;
        }
        $scoringInput = $this->scoringInputFactory->from(
            $normalized,
            $nativeSpf,
            $nativeDmarc,
            $nativeDkim,
            $nativeMtaSts,
            $nativeTlsRpt,
            $nativeMx,
            $nativeCertificate,
            $nativeBimi,
        );
        $scoreResult = $this->scoreCalculator->calculate($scoringInput);
        $recommendationList = $this->recommendationEngine->build($domain, $scanResult);

        $resultJson = $scanResult->toArray();
        $dmarcDnsCompat = $nativeCollection->artifacts[ScanArtifactKeys::DMARC_DNS_COMPAT] ?? null;
        if (is_array($dmarcDnsCompat) && isset($resultJson['dns']['records']) && is_array($resultJson['dns']['records'])) {
            $resultJson['dns']['records']['DMARC'] = $dmarcDnsCompat;
        }
        $dkimDnsCompat = $nativeCollection->artifacts[ScanArtifactKeys::DKIM_DNS_COMPAT] ?? null;
        if (is_array($dkimDnsCompat) && isset($resultJson['dns']['records']) && is_array($resultJson['dns']['records'])) {
            $resultJson['dns']['records']['DKIM'] = $dkimDnsCompat;
        }
        $mtaStsDnsCompat = $nativeCollection->artifacts[ScanArtifactKeys::MTA_STS_DNS_COMPAT] ?? null;
        if (is_array($mtaStsDnsCompat) && isset($resultJson['dns']['records']) && is_array($resultJson['dns']['records'])) {
            $resultJson['dns']['records']['MTA-STS'] = $mtaStsDnsCompat;
        }
        $tlsRptDnsCompat = $nativeCollection->artifacts[ScanArtifactKeys::TLS_RPT_DNS_COMPAT] ?? null;
        if (is_array($tlsRptDnsCompat) && isset($resultJson['dns']['records']) && is_array($resultJson['dns']['records'])) {
            $resultJson['dns']['records']['TLS-RPT'] = $tlsRptDnsCompat;
        }
        $mxDnsCompat = $nativeCollection->artifacts[ScanArtifactKeys::MX_DNS_COMPAT] ?? null;
        if (is_array($mxDnsCompat) && isset($resultJson['dns']['records']) && is_array($resultJson['dns']['records'])) {
            $resultJson['dns']['records']['MX'] = $mxDnsCompat;
        }
        $bimiDnsCompat = $nativeCollection->artifacts[ScanArtifactKeys::BIMI_DNS_COMPAT] ?? null;
        if (is_array($bimiDnsCompat) && isset($resultJson['dns']['records']) && is_array($resultJson['dns']['records'])) {
            $resultJson['dns']['records']['BIMI'] = $bimiDnsCompat;
        }
        if ($scoreResult->total !== null) {
            if (isset($resultJson['dns'])) {
                $resultJson['dns']['score'] = $scoreResult->total;
                $resultJson['dns']['score_breakdown'] = $scoreResult->breakdown;
            } elseif ($scoreResult->breakdown !== []) {
                $spf = is_array($resultJson['spf'] ?? null) ? $resultJson['spf'] : [];
                $resultJson['dns'] = [
                    'score' => $scoreResult->total,
                    'score_breakdown' => $scoreResult->breakdown,
                    'records' => [
                        'SPF' => isset($spf['record']) && is_string($spf['record']) && $spf['record'] !== ''
                            ? ['status' => 'found', 'data' => $spf['record']]
                            : ['status' => 'missing'],
                    ],
                ];
            }
        }
        $onProgress && $onProgress('complete', ScanPayloadBuilder::buildBroadcastReport($resultJson) + ['domain' => $domain->domain]);

        return new ScanExecutionResultDTO(
            resultJson: $resultJson,
            recommendations: $recommendationList->items,
            score: $scoreResult->total,
            durationMs: (int) round((microtime(true) - $startTime) * 1000),
            scanType: $context->scanType,
            spfRawResult: $spfRawResult,
        );
    }
}
