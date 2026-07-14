<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Compatibility\SpfLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use Tests\TestCase;

class SpfLegacyPayloadAdapterTest extends TestCase
{
    public function test_exactly_ten_lookups_maps_to_warning_not_error(): void
    {
        $native = new SpfNativeResult(
            state: SpfStates::WARNING,
            protocolStatus: SpfProtocolStatus::VALID,
            riskStatus: SpfRiskStatus::WARNING,
            summary: 'SPF configuration valid; lookup budget at limit (10/10).',
            rawRecord: 'v=spf1 -all',
            normalizedRecord: 'v=spf1 -all',
            parsedTerms: [],
            parsedTerminalPolicy: ['qualifier' => '-', 'mechanism' => 'all', 'position' => 1],
            terminalPolicy: \App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy::HARD_FAIL,
            lookupCount: 10,
            lookupLimit: 10,
            lookupsRemaining: 0,
            voidLookupCount: 0,
            lookupPaths: [],
            recursiveDependencies: [],
            resolvedIps: [],
            flattenedRecord: 'v=spf1 -all',
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
            discovery: ['source' => 'dns_collection'],
        );

        $payload = (new SpfLegacyPayloadAdapter())->toResultJsonSpf($native);

        $this->assertSame('warning', $payload['status']);
        $this->assertTrue($payload['valid']);
        $this->assertSame(10, $payload['lookups']);
        $this->assertSame('valid', $payload['protocol_status']);
        $this->assertIsArray($payload['analysis']);
        $this->assertSame('spf-native-v1', $payload['analysis']['version']);
        $this->assertSame(SpfTerminalPolicy::HARD_FAIL, $payload['analysis']['terminal_policy']);
        $this->assertArrayNotHasKey('terminal_policy', $payload);
    }
}
