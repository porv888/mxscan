<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Compatibility\SpfLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluator;
use App\Domain\EmailSecurity\Checks\SPF\Evidence\SpfEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidator;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class SpfCheck implements SecurityCheckInterface
{
    public function __construct(
        private SpfRecordDiscovery $discovery,
        private SpfParser $parser,
        private SpfValidator $validator,
        private SpfEvaluator $evaluator,
        private SpfEvidenceBuilder $evidenceBuilder,
        private SpfLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'spf';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $domain = $context->domainName;
        $spfDiscovery = $this->discovery->discover($domain, $dns);

        if ($spfDiscovery->hasDnsFailure()) {
            $native = $this->buildUnknownResult($spfDiscovery);
        } elseif ($spfDiscovery->isMissing()) {
            $native = $this->buildMissingResult($spfDiscovery);
        } else {
            $record = (string) $spfDiscovery->record;
            $terms = $this->parser->parse($record, $domain);
            $validation = $this->validator->validate($terms, $spfDiscovery, $record);
            $evaluation = $this->evaluator->evaluate($terms, $domain, $validation);
            $native = $this->evidenceBuilder->build(
                $spfDiscovery,
                $validation,
                $evaluation,
                $this->evaluator->lookupCounter(),
            );
        }

        $legacyPayload = $this->legacyAdapter->toResultJsonSpf($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'spf',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::LEGACY_SPF_RAW => $this->legacyAdapter->toSpfResultDto($native),
                ScanArtifactKeys::NATIVE_SPF_RESULT => $native,
            ],
        );
    }

    private function buildMissingResult(\App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult $discovery): SpfNativeResult
    {
        return new SpfNativeResult(
            state: SpfStates::MISSING,
            summary: 'No SPF record found.',
            rawRecord: null,
            normalizedRecord: null,
            parsedTerms: [],
            terminalPolicy: null,
            lookupCount: 0,
            lookupLimit: 10,
            lookupsRemaining: 10,
            voidLookupCount: 0,
            lookupPaths: [],
            recursiveDependencies: [],
            resolvedIps: [],
            flattenedRecord: null,
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
            discovery: [
                'source' => $discovery->source,
                'domain' => $discovery->domain,
                'txt_evidence' => $discovery->txtEvidence,
                'multiple_records' => false,
                'dns_failure' => false,
            ],
        );
    }

    private function buildUnknownResult(\App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult $discovery): SpfNativeResult
    {
        return new SpfNativeResult(
            state: SpfStates::UNKNOWN,
            summary: 'SPF record discovery failed due to DNS resolver error.',
            rawRecord: null,
            normalizedRecord: null,
            parsedTerms: [],
            terminalPolicy: null,
            lookupCount: 0,
            lookupLimit: 10,
            lookupsRemaining: 10,
            voidLookupCount: 0,
            lookupPaths: [],
            recursiveDependencies: [],
            resolvedIps: [],
            flattenedRecord: null,
            errors: [['code' => 'DNS_FAILURE', 'message' => $discovery->dnsError ?? 'DNS lookup failed']],
            warnings: [],
            resolverDiagnostics: [['type' => 'TXT', 'host' => $discovery->domain, 'error' => $discovery->dnsError]],
            discovery: [
                'source' => $discovery->source,
                'domain' => $discovery->domain,
                'txt_evidence' => $discovery->txtEvidence,
                'multiple_records' => false,
                'dns_failure' => true,
            ],
        );
    }
}
