<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDiscoveryResult;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiSelectorContext;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiIndicatorPreviewStore;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class BimiEvidenceBuilder
{
    public function __construct(
        private BimiSelectorResolver $selectorResolver,
        private BimiAssertionDiscovery $discovery,
        private BimiRecordValidator $recordValidator,
        private BimiRecordParser $recordParser,
        private BimiIndicatorFetcher $indicatorFetcher,
        private BimiEvidenceDocumentFetcher $evidenceDocumentFetcher,
        private BimiMarkCertificateValidator $markCertificateValidator,
        private BimiIndicatorComparator $indicatorComparator,
        private BimiDmarcEligibilityEvaluator $dmarcEligibilityEvaluator,
        private BimiProviderReadinessEvaluator $providerReadinessEvaluator,
        private BimiStatusDeriver $statusDeriver,
        private BimiIndicatorPreviewStore $indicatorPreviewStore,
    ) {
    }

    public function build(
        CheckContextDTO $context,
        ?DnsCollectionResultDTO $dns,
        ?DmarcNativeResult $dmarcNative,
    ): BimiNativeResult {
        $domain = strtolower(rtrim(trim($context->domainName), '.'));
        $selectorContext = $this->selectorResolver->resolve($context);
        $discovery = $this->discovery->discover($domain, $selectorContext, $dns);

        $errors = [];
        $warnings = [];
        $evaluationCompleteness = 'complete';
        $localPartEvaluation = [
            'complete' => true,
            'test_local_part' => $selectorContext->testLocalPart,
        ];

        if ($discovery->hasDnsFailure()) {
            $status = $this->statusDeriver->derive($discovery, [], $errors, $warnings);

            return $this->nativeFromStatus($domain, $discovery, $status, [], [], [], [], [], [], $localPartEvaluation, $errors, $warnings, false);
        }

        if ($discovery->isMissing()) {
            $status = $this->statusDeriver->derive($discovery, [], $errors, $warnings);
            $dmarcEligibility = $this->dmarcEligibilityEvaluator->evaluate($dmarcNative, $domain, null);

            return $this->nativeFromStatus(
                $domain,
                $discovery,
                $status,
                $this->emptyRecordPayload($discovery),
                $this->selectorPayload($selectorContext),
                $this->discoveryPayload($discovery),
                ['status' => 'absent'],
                ['status' => BimiEvidenceStatus::ABSENT],
                [],
                $dmarcEligibility,
                $localPartEvaluation,
                $errors,
                $warnings,
                false,
            );
        }

        $recordValidation = $this->recordValidator->validateDiscovery($discovery);
        $errors = array_merge($errors, $recordValidation['errors']);
        $warnings = array_merge($warnings, $recordValidation['warnings']);
        $parsed = $recordValidation['parsed'] ?? ($discovery->record !== null ? $this->recordParser->parse($discovery->record) : null);
        $recordPayload = $this->recordPayload($discovery, $parsed);

        if ($parsed !== null && $parsed->lpsPrefixes !== [] && $selectorContext->testLocalPart === null) {
            $evaluationCompleteness = 'partial';
            $localPartEvaluation['complete'] = false;
            $warnings[] = [
                'code' => 'LOCAL_PART_NOT_SUPPLIED',
                'message' => 'Local-part selector evaluation is incomplete.',
            ];
        }

        if (($recordValidation['declined'] ?? false) === true) {
            $status = $this->statusDeriver->derive($discovery, ['declined' => true], [], $warnings);
            $dmarcEligibility = $this->dmarcEligibilityEvaluator->evaluate($dmarcNative, $domain, null);

            return $this->nativeFromStatus(
                $domain,
                $discovery,
                $status,
                $recordPayload,
                $this->selectorPayload($selectorContext),
                $this->discoveryPayload($discovery),
                ['status' => 'declined'],
                ['status' => BimiEvidenceStatus::ABSENT],
                [],
                $dmarcEligibility,
                $localPartEvaluation,
                $errors,
                $warnings,
                $warnings !== [],
            );
        }

        if (!($recordValidation['valid'] ?? false)) {
            $status = $this->statusDeriver->derive($discovery, ['evaluation_completeness' => $evaluationCompleteness], $errors, $warnings);
            $dmarcEligibility = $this->dmarcEligibilityEvaluator->evaluate($dmarcNative, $domain, null);

            return $this->nativeFromStatus(
                $domain,
                $discovery,
                $status,
                $recordPayload,
                $this->selectorPayload($selectorContext),
                $this->discoveryPayload($discovery),
                ['status' => 'not_checked'],
                ['status' => BimiEvidenceStatus::INVALID],
                [],
                $dmarcEligibility,
                $localPartEvaluation,
                $errors,
                $warnings,
                $warnings !== [],
            );
        }

        $indicator = ['status' => 'absent'];
        $authorityEvidence = ['status' => BimiEvidenceStatus::ABSENT];
        $indicatorComparison = [];

        $logoUri = $parsed?->tag('l');
        if (is_string($logoUri) && $logoUri !== '') {
            $indicator = $this->indicatorFetcher->fetch($logoUri);
            foreach ($indicator['fetch']['errors'] ?? [] as $fetchError) {
                $errors[] = $fetchError;
            }
            foreach ($indicator['fetch']['warnings'] ?? [] as $fetchWarning) {
                $warnings[] = $fetchWarning;
            }

            $indicator = $this->attachPreviewRef($context, $indicator);
        }

        $authorityUri = $parsed?->tag('a');
        if ($authorityUri === null || $authorityUri === '') {
            if ($parsed?->tagPresent('a') === true && ($parsed->tagRaw('a') ?? '') === '') {
                $authorityEvidence = ['status' => BimiEvidenceStatus::SELF_ASSERTED];
            } else {
                $authorityEvidence = ['status' => BimiEvidenceStatus::ABSENT];
            }
        } else {
            $evidenceFetch = $this->evidenceDocumentFetcher->fetch($authorityUri);
            foreach ($evidenceFetch['fetch']['errors'] ?? [] as $fetchError) {
                $errors[] = $fetchError;
            }

            if (($evidenceFetch['status'] ?? '') === 'unavailable') {
                $authorityEvidence = ['status' => BimiEvidenceStatus::UNAVAILABLE, 'fetch' => $evidenceFetch['fetch']];
            } elseif (($evidenceFetch['status'] ?? '') === 'malformed') {
                $authorityEvidence = ['status' => BimiEvidenceStatus::INVALID, 'fetch' => $evidenceFetch['fetch']];
            } else {
                $certValidation = $this->markCertificateValidator->validate(
                    $evidenceFetch['certificates'] ?? [],
                    $domain,
                );
                $authorityEvidence = array_merge([
                    'status' => $this->mapCertStatus($certValidation['status'] ?? 'invalid'),
                    'type' => $certValidation['type'] ?? null,
                    'fetch' => $evidenceFetch['fetch'],
                    'validation' => $certValidation,
                ], $certValidation);

                foreach ($certValidation['errors'] ?? [] as $certError) {
                    $errors[] = $certError;
                }
                foreach ($certValidation['warnings'] ?? [] as $certWarning) {
                    $warnings[] = $certWarning;
                }

                $embeddedHash = $certValidation['embedded_indicator_hash'] ?? null;
                $indicatorComparison = $this->indicatorComparator->compare(
                    $indicator['sha256'] ?? null,
                    is_string($embeddedHash) ? $embeddedHash : null,
                );

                if (($indicatorComparison['completeness'] ?? '') === 'complete'
                    && ($indicatorComparison['identical'] ?? null) === false) {
                    $errors[] = [
                        'code' => 'INDICATOR_MISMATCH',
                        'message' => 'Published logo does not match embedded certificate indicator.',
                    ];
                }
            }
        }

        $orgDomain = $discovery->fallbackPath[count($discovery->fallbackPath) - 1]['domain'] ?? $domain;
        $dmarcEligibility = $this->dmarcEligibilityEvaluator->evaluate($dmarcNative, $domain, is_string($orgDomain) ? $orgDomain : $domain);

        $analysisContext = [
            'protocol_status' => BimiProtocolStatus::VALID,
            'indicator' => $indicator,
            'authority_evidence' => $authorityEvidence,
            'dmarc_eligibility' => $dmarcEligibility,
            'evaluation_completeness' => $evaluationCompleteness,
            'evidence_status' => (string) ($authorityEvidence['status'] ?? BimiEvidenceStatus::ABSENT),
            'declined' => false,
        ];

        $providerProfiles = $this->providerReadinessEvaluator->evaluateProfiles($analysisContext);
        $status = $this->statusDeriver->derive($discovery, $analysisContext, $errors, $warnings);

        return $this->nativeFromStatus(
            $domain,
            $discovery,
            $status,
            $recordPayload,
            $this->selectorPayload($selectorContext),
            $this->discoveryPayload($discovery),
            $indicator,
            $authorityEvidence,
            $indicatorComparison,
            $dmarcEligibility,
            $localPartEvaluation,
            $errors,
            $warnings,
            $warnings !== [],
            $providerProfiles,
        );
    }

    /**
     * @param array{protocol_status: string, readiness_status: string, evidence_status: string, risk_status: string, state: string, summary: string, evaluation_completeness: string} $status
     * @param array<string, mixed> $recordPayload
     * @param array<string, mixed> $selectorPayload
     * @param array<string, mixed> $discoveryPayload
     * @param array<string, mixed> $indicator
     * @param array<string, mixed> $authorityEvidence
     * @param array<string, mixed> $indicatorComparison
     * @param array<string, mixed> $dmarcEligibility
     * @param array<string, mixed> $localPartEvaluation
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $providerProfiles
     */
    private function nativeFromStatus(
        string $domain,
        BimiDiscoveryResult $discovery,
        array $status,
        array $recordPayload,
        array $selectorPayload,
        array $discoveryPayload,
        array $indicator,
        array $authorityEvidence,
        array $indicatorComparison,
        array $dmarcEligibility,
        array $localPartEvaluation,
        array $errors,
        array $warnings,
        bool $hasMaterialWarnings,
        array $providerProfiles = [],
    ): BimiNativeResult {
        return new BimiNativeResult(
            state: $status['state'],
            protocolStatus: $status['protocol_status'],
            readinessStatus: $status['readiness_status'],
            evidenceStatus: $status['evidence_status'],
            riskStatus: $status['risk_status'],
            summary: $status['summary'],
            domain: $domain,
            recordHostname: $discovery->recordHostname,
            evaluationCompleteness: $status['evaluation_completeness'],
            rawRecord: $discovery->record,
            record: $recordPayload,
            selector: $selectorPayload,
            discovery: $discoveryPayload,
            indicator: $indicator,
            authorityEvidence: $authorityEvidence,
            indicatorComparison: $indicatorComparison,
            dmarcEligibility: $dmarcEligibility,
            providerProfiles: $providerProfiles,
            localPartEvaluation: $localPartEvaluation,
            standardsProfile: config('bimi.standards_profile', []),
            errors: $errors,
            warnings: $warnings,
            resolverDiagnostics: $discovery->resolverDiagnostics,
            hasMaterialWarnings: $hasMaterialWarnings,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function recordPayload(BimiDiscoveryResult $discovery, $parsed): array
    {
        return [
            'raw' => $discovery->record,
            'normalized' => $parsed?->normalizedRecord ?? $discovery->record,
            'ttl' => $discovery->ttl,
            'alias_path' => $discovery->aliasPath,
            'tags' => $parsed?->tags ?? [],
            'avatar_preference' => $parsed?->avatarPreference ?? 'brand',
            'lps_prefixes' => $parsed?->lpsPrefixes ?? [],
            'declined' => $parsed?->declined ?? false,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function emptyRecordPayload(BimiDiscoveryResult $discovery): array
    {
        return [
            'raw' => null,
            'normalized' => null,
            'ttl' => $discovery->ttl,
            'alias_path' => $discovery->aliasPath,
            'tags' => [],
            'avatar_preference' => 'brand',
            'lps_prefixes' => [],
            'declined' => false,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function selectorPayload(BimiSelectorContext $selectorContext): array
    {
        return [
            'value' => $selectorContext->value,
            'source' => $selectorContext->source,
            'test_local_part' => $selectorContext->testLocalPart,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function discoveryPayload(BimiDiscoveryResult $discovery): array
    {
        return [
            'queried_domain' => $discovery->queriedDomain,
            'record_hostname' => $discovery->recordHostname,
            'source' => $discovery->source,
            'selector' => $discovery->selector,
            'selector_source' => $discovery->selectorSource,
            'fallback_path' => $discovery->fallbackPath,
            'selected_record_count' => $discovery->selectedRecordCount,
        ];
    }

    private function mapCertStatus(string $status): string
    {
        return match ($status) {
            'valid' => BimiEvidenceStatus::VALID,
            'partially_validated' => BimiEvidenceStatus::PARTIALLY_VALIDATED,
            'unsupported' => BimiEvidenceStatus::UNSUPPORTED,
            'unavailable' => BimiEvidenceStatus::UNAVAILABLE,
            default => BimiEvidenceStatus::INVALID,
        };
    }

    /**
     * @param array<string, mixed> $indicator
     * @return array<string, mixed>
     */
    private function attachPreviewRef(CheckContextDTO $context, array $indicator): array
    {
        $decompressedSvg = $indicator['_decompressed_svg'] ?? null;
        unset($indicator['_decompressed_svg']);

        if (($indicator['status'] ?? '') !== 'valid'
            || !is_string($decompressedSvg)
            || $decompressedSvg === ''
            || !is_string($indicator['sha256'] ?? null)
            || $indicator['sha256'] === ''
            || $context->scanId === null
            || $context->scanId === '') {
            return $indicator;
        }

        if ($this->indicatorPreviewStore->store($context->scanId, $indicator['sha256'], $decompressedSvg)) {
            $indicator['preview_ref'] = [
                'scan_id' => $context->scanId,
                'sha256' => $indicator['sha256'],
            ];
        }

        return $indicator;
    }
}
