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
        $scoringInput = $this->scoringInputFactory->from($normalized, $nativeSpf);
        $scoreResult = $this->scoreCalculator->calculate($scoringInput);
        $recommendationList = $this->recommendationEngine->build($domain, $scanResult);

        $resultJson = $scanResult->toArray();
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
