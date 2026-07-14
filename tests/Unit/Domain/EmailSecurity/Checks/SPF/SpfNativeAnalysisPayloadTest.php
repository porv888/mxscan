<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Compatibility\SpfNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\SPF\SpfEvaluationCompleteness;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use Tests\Support\EmailSecurity\SpfNativeResultFactory;
use Tests\TestCase;

class SpfNativeAnalysisPayloadTest extends TestCase
{
    public function test_builds_full_native_analysis_contract(): void
    {
        $native = SpfNativeResultFactory::make(
            lookupCount: 4,
            warnings: [['code' => 'VOID_LOOKUP_WARNING', 'message' => 'elevated']],
        );
        $native = new \App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult(
            state: $native->state,
            protocolStatus: $native->protocolStatus,
            riskStatus: $native->riskStatus,
            summary: $native->summary,
            rawRecord: $native->rawRecord,
            normalizedRecord: $native->normalizedRecord,
            parsedTerms: $native->parsedTerms,
            parsedTerminalPolicy: $native->parsedTerminalPolicy,
            terminalPolicy: $native->terminalPolicy,
            lookupCount: 4,
            lookupLimit: 10,
            lookupsRemaining: 6,
            voidLookupCount: 1,
            lookupPaths: $native->lookupPaths,
            recursiveDependencies: [
                ['mechanism' => 'include', 'domain' => 'spf.example.com', 'record' => 'v=spf1 -all'],
            ],
            resolvedIps: $native->resolvedIps,
            flattenedRecord: $native->flattenedRecord,
            errors: $native->errors,
            warnings: $native->warnings,
            resolverDiagnostics: $native->resolverDiagnostics,
            discovery: $native->discovery,
        );

        $analysis = (new SpfNativeAnalysisPayload())->fromNative($native);

        $this->assertSame('spf-native-v1', $analysis['version']);
        $this->assertSame('valid', $analysis['protocol_status']);
        $this->assertSame('healthy', $analysis['risk_status']);
        $this->assertSame('pass', $analysis['state']);
        $this->assertSame(SpfTerminalPolicy::HARD_FAIL, $analysis['terminal_policy']);
        $this->assertSame(4, $analysis['lookup_count']);
        $this->assertSame(10, $analysis['lookup_limit']);
        $this->assertSame(6, $analysis['lookups_remaining']);
        $this->assertSame(1, $analysis['void_lookup_count']);
        $this->assertSame(SpfEvaluationCompleteness::COMPLETE, $analysis['evaluation_completeness']);
        $this->assertSame([['mechanism' => 'include', 'domain' => 'spf.example.com']], $analysis['dependencies']);
        $this->assertArrayNotHasKey('record', $analysis['dependencies'][0]);
    }

    public function test_partial_evaluation_completeness_for_temperror(): void
    {
        $native = SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::TEMPERROR,
            summary: 'SPF configuration could not be fully evaluated.',
        );

        $analysis = (new SpfNativeAnalysisPayload())->fromNative($native);

        $this->assertSame(SpfEvaluationCompleteness::PARTIAL, $analysis['evaluation_completeness']);
    }
}
