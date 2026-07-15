<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Evidence;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateEvidenceProvider;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateMtaStsCompatMapper;
use App\Domain\EmailSecurity\Checks\MtaSts\Discovery\MtaStsDiscoveryResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Discovery\MtaStsDnsRecordDiscovery;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetcher;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetchResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Matching\MtaStsMxMatcher;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsPolicyParser;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsDnsRecordValidator;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidator;
use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxEvidenceProviderInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class MtaStsEvidenceBuilder
{
    public function __construct(
        private MtaStsDnsRecordDiscovery $discovery,
        private MtaStsDnsRecordValidator $dnsValidator,
        private MtaStsPolicyFetcher $policyFetcher,
        private MtaStsPolicyParser $policyParser,
        private MtaStsPolicyValidator $policyValidator,
        private CertificateEvidenceProvider $certificateEvidenceProvider,
        private CertificateMtaStsCompatMapper $certificateCompatMapper,
        private MxEvidenceProviderInterface $mxEvidenceProvider,
        private MtaStsMxMatcher $mxMatcher,
        private MtaStsStatusDeriver $statusDeriver,
    ) {
    }

    public function build(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): MtaStsNativeResult
    {
        $domain = strtolower(rtrim(trim($context->domainName), '.'));
        $discovery = $this->discovery->discover($domain, $dns);
        $errors = [];
        $warnings = [];
        $resolverDiagnostics = $discovery->resolverDiagnostics;

        if ($discovery->hasDnsFailure()) {
            $status = $this->statusDeriver->derive($discovery, null, null, null, null, [], [], [[
                'code' => 'DNS_FAILURE',
                'message' => $discovery->dnsError ?? 'DNS lookup failed',
            ]], []);

            return $this->nativeFromStatus($domain, $discovery, $status, [], [], [], [], [], $errors, $warnings, $resolverDiagnostics);
        }

        if ($discovery->isMissing()) {
            $status = $this->statusDeriver->derive($discovery, null, null, null, null, [], [], [], []);

            return $this->nativeFromStatus($domain, $discovery, $status, [], [], [], [], [], $errors, $warnings, $resolverDiagnostics);
        }

        $dnsValidation = $this->dnsValidator->validate($discovery);
        $errors = array_merge($errors, $dnsValidation->errors);
        $warnings = array_merge($warnings, $dnsValidation->warnings);

        if (!$dnsValidation->valid) {
            $status = $this->statusDeriver->derive($discovery, $dnsValidation, null, null, null, [], [], $errors, $warnings);

            return $this->nativeFromStatus($domain, $discovery, $status, $this->dnsIndicator($discovery, $dnsValidation), [], [], [], [], $errors, $warnings, $resolverDiagnostics);
        }

        $policyFetch = $this->policyFetcher->fetch($domain);
        $policyFetchPayload = $this->policyFetchPayload($policyFetch);

        if (!$policyFetch->isSuccess()) {
            if ($policyFetch->contentType !== null && !str_starts_with(strtolower($policyFetch->contentType), 'text/plain')) {
                $warnings[] = [
                    'code' => 'UNEXPECTED_CONTENT_TYPE',
                    'message' => 'Policy endpoint returned unexpected Content-Type.',
                ];
            }

            $status = $this->statusDeriver->derive($discovery, $dnsValidation, $policyFetch, null, null, [], [], $errors, $warnings);

            return $this->nativeFromStatus(
                $domain,
                $discovery,
                $status,
                $this->dnsIndicator($discovery, $dnsValidation),
                $policyFetchPayload,
                [],
                [],
                [],
                $errors,
                $warnings,
                $resolverDiagnostics,
            );
        }

        if ($policyFetch->contentType !== null && !str_starts_with(strtolower($policyFetch->contentType), 'text/plain')) {
            $warnings[] = [
                'code' => 'UNEXPECTED_CONTENT_TYPE',
                'message' => 'Policy endpoint returned unexpected Content-Type.',
            ];
        }

        $policyHostEvaluation = $this->certificateEvidenceProvider->obtainEndpointEvaluation(
            $context,
            CertificateEndpoint::mtaStsHttps($domain),
        );
        $policyHostTls = $this->certificateCompatMapper->toPolicyHostTls($policyHostEvaluation);

        $parsedPolicy = $this->policyParser->parse((string) $policyFetch->body);
        $policyValidation = $this->policyValidator->validate($parsedPolicy);
        $errors = array_merge($errors, $policyValidation->errors);
        $warnings = array_merge($warnings, $policyValidation->warnings);

        $mxEvidence = $this->mxEvidenceProvider->provide($context);
        $mxHosts = array_map(
            fn (array $host) => [
                'hostname' => $host['hostname'],
                'priority' => $host['priority'],
                'normalized_hostname' => $host['normalized_hostname'],
            ],
            $mxEvidence->hosts,
        );
        $mxMatches = $this->mxMatcher->match($mxHosts, $policyValidation->validMxPatterns);

        $smtpEvaluations = [];
        if ($policyValidation->mode !== 'none') {
            foreach ($mxHosts as $mxHost) {
                $hostname = CertificateEndpoint::normalizeHostname((string) ($mxHost['hostname'] ?? ''));
                if ($hostname === '') {
                    continue;
                }

                $smtpEvaluations[$hostname] = $this->certificateEvidenceProvider->obtainEndpointEvaluation(
                    $context,
                    CertificateEndpoint::smtpMx($hostname, (int) ($mxHost['priority'] ?? 0)),
                );
            }
        }

        $mxValidation = $this->mxValidationPayload($mxMatches, $smtpEvaluations);

        $status = $this->statusDeriver->derive(
            $discovery,
            $dnsValidation,
            $policyFetch,
            $policyHostTls,
            $policyValidation,
            $mxMatches,
            $mxValidation,
            $errors,
            $warnings,
        );

        $policyPayload = [
            'version' => $parsedPolicy->version,
            'mode' => $policyValidation->mode,
            'max_age' => $policyValidation->maxAge,
            'mx_patterns' => $policyValidation->validMxPatterns,
            'unknown_fields' => $parsedPolicy->unknownFields,
        ];

        return $this->nativeFromStatus(
            $domain,
            $discovery,
            $status,
            $this->dnsIndicator($discovery, $dnsValidation),
            $policyFetchPayload,
            $policyHostTls,
            $policyPayload,
            $mxValidation,
            $errors,
            $warnings,
            $resolverDiagnostics,
        );
    }

    /**
     * @param array{protocol_status: string, risk_status: string, state: string, summary: string, evaluation_completeness: string} $status
     * @param list<array<string, mixed>> $mxValidation
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    private function nativeFromStatus(
        string $domain,
        MtaStsDiscoveryResult $discovery,
        array $status,
        array $dnsIndicator,
        array $policyFetch,
        array $policyHostTls,
        array $policy,
        array $mxValidation,
        array $errors,
        array $warnings,
        array $resolverDiagnostics,
    ): MtaStsNativeResult {
        return new MtaStsNativeResult(
            state: $status['state'],
            protocolStatus: $status['protocol_status'],
            riskStatus: $status['risk_status'],
            summary: $status['summary'],
            domain: $domain,
            evaluationCompleteness: $status['evaluation_completeness'],
            rawIndicator: $discovery->record,
            dnsIndicator: $dnsIndicator,
            policyFetch: $policyFetch,
            policyHostTls: $policyHostTls,
            policy: $policy,
            mxValidation: $mxValidation,
            errors: $errors,
            warnings: $warnings,
            resolverDiagnostics: $resolverDiagnostics,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function dnsIndicator(MtaStsDiscoveryResult $discovery, $dnsValidation): array
    {
        return [
            'hostname' => $discovery->hostname,
            'status' => $dnsValidation->valid ? 'valid' : 'invalid',
            'raw_record' => $discovery->record,
            'policy_id' => $dnsValidation->policyId,
            'ttl' => $discovery->ttl,
            'cname_path' => $discovery->cnamePath,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function policyFetchPayload(MtaStsPolicyFetchResult $fetch): array
    {
        return [
            'url' => $fetch->url,
            'status' => $fetch->status,
            'http_status' => $fetch->httpStatus,
            'content_type' => $fetch->contentType,
            'duration_ms' => $fetch->durationMs,
            'failure_category' => $fetch->failureCategory,
            'body_preview' => $fetch->bodyPreview,
        ];
    }

    /**
     * @param list<\App\Domain\EmailSecurity\Checks\MtaSts\Matching\MtaStsMxMatchResult> $mxMatches
     * @param array<string, CertificateEndpointEvaluation> $smtpEvaluations
     * @return list<array<string, mixed>>
     */
    private function mxValidationPayload(array $mxMatches, array $smtpEvaluations): array
    {
        $rows = [];
        foreach ($mxMatches as $match) {
            $evaluation = $smtpEvaluations[$match->hostname] ?? null;
            $smtpTls = $evaluation !== null ? $this->certificateCompatMapper->toSmtpTls($evaluation) : null;

            $rows[] = [
                'hostname' => $match->hostname,
                'priority' => $match->priority,
                'matches_policy' => $match->matchesPolicy,
                'matched_pattern' => $match->matchedPattern,
                'mismatch_reason' => $match->mismatchReason,
                'starttls' => $evaluation === null
                    ? null
                    : $evaluation->failureCategory !== 'starttls_not_advertised',
                'certificate_valid' => $evaluation !== null
                    && in_array($evaluation->certificateStatus, [
                        \App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation::CERTIFICATE_VALID,
                        \App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation::CERTIFICATE_WARNING,
                    ], true),
                'hostname_match' => $evaluation?->hostnameMatch ?? false,
                'smtp_tls' => $smtpTls,
            ];
        }

        return $rows;
    }
}
