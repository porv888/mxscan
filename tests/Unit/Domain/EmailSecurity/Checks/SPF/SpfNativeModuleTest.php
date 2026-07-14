<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Compatibility\SpfLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfLookupCounter;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Services\Spf\SpfResolver;
use Tests\TestCase;

class SpfNativeModuleTest extends TestCase
{
    public function test_parser_mechanisms_qualifiers_and_modifiers(): void
    {
        $terms = (new SpfParser())->parse('v=spf1 +ip4:1.2.3.4 include:example.com -all redirect=other.test exp=explain', 'example.test');

        $this->assertSame('include', $terms[1]->name);
        $this->assertSame('+', $terms[0]->qualifier);
        $this->assertSame('-', $terms[2]->qualifier);
        $this->assertSame('redirect', $terms[3]->name);
        $this->assertSame('exp', $terms[4]->name);
    }

    public function test_unknown_mechanism_produces_structured_error(): void
    {
        $terms = (new SpfParser())->parse('v=spf1 foo:bar -all', 'example.test');
        $this->assertSame('unknown', $terms[0]->name);
        $this->assertNotEmpty($terms[0]->errors);
    }

    public function test_discovers_from_dns_collection_without_resolver_call(): void
    {
        $resolver = new SpfDnsDependencyResolver(new \App\Services\Dns\DnsClient());

        $dns = new DnsCollectionResultDTO(
            records: ['SPF' => ['status' => 'found', 'data' => 'v=spf1 -all']],
            score: 20,
            scoreBreakdown: [],
            legacyDnsPayload: [],
            rootTxtRecords: [
                ['host' => 'example.test', 'txt' => 'v=spf1 -all', 'ttl' => 300],
                ['host' => 'example.test', 'txt' => 'google-site-verification=abc', 'ttl' => 300],
            ],
        );

        $result = (new SpfRecordDiscovery($resolver))->discover('example.test', $dns);

        $this->assertSame('v=spf1 -all', $result->record);
        $this->assertSame('dns_collection', $result->source);
    }

    public function test_detects_multiple_spf_records(): void
    {
        $resolver = new SpfDnsDependencyResolver(new \App\Services\Dns\DnsClient());
        $dns = new DnsCollectionResultDTO(
            records: [],
            score: 0,
            scoreBreakdown: [],
            legacyDnsPayload: [],
            rootTxtRecords: [
                ['host' => 'example.test', 'txt' => 'v=spf1 -all', 'ttl' => 300],
                ['host' => 'example.test', 'txt' => 'v=spf1 include:other.test -all', 'ttl' => 300],
            ],
        );

        $result = (new SpfRecordDiscovery($resolver))->discover('example.test', $dns);
        $this->assertTrue($result->multipleRecords);
    }

    public function test_joins_split_txt_chunks(): void
    {
        $joined = SpfRecordDiscovery::joinTxtChunks(['v=spf1', ' include:example.com ', '-all']);
        $this->assertSame('v=spf1 include:example.com -all', $joined);
    }

    public function test_unknown_modifier_is_ignored(): void
    {
        $terms = (new SpfParser())->parse('v=spf1 ara=foo -all', 'example.test');
        $this->assertSame('modifier', $terms[0]->type);
        $this->assertSame('ara', $terms[0]->name);
        $this->assertEmpty((new \App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidator())->validate($terms, new \App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult('example.test', 'dns_collection', 'v=spf1 ara=foo -all'), 'v=spf1 ara=foo -all')->errors);
    }

    public function test_lookup_counter_thresholds(): void
    {
        $counter = new SpfLookupCounter();
        for ($i = 0; $i < 7; $i++) {
            $counter->increment('include', "inc{$i}.test", 'TXT');
        }

        $this->assertSame(7, $counter->count());
        $this->assertSame(3, $counter->remaining());
        $this->assertFalse($counter->exceeded());
    }

    public function test_legacy_payload_preserves_status_thresholds(): void
    {
        $native = new SpfNativeResult(
            state: SpfStates::WARNING,
            protocolStatus: \App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus::VALID,
            riskStatus: \App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus::WARNING,
            summary: 'near limit',
            rawRecord: 'v=spf1 -all',
            normalizedRecord: 'v=spf1 -all',
            parsedTerms: [],
            parsedTerminalPolicy: ['qualifier' => '-', 'mechanism' => 'all', 'position' => 1],
            terminalPolicy: \App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy::HARD_FAIL,
            lookupCount: 9,
            lookupLimit: 10,
            lookupsRemaining: 1,
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
        $this->assertSame(9, $payload['lookups']);
    }

    public function test_multiple_spf_maps_to_legacy_warning_code(): void
    {
        $native = new SpfNativeResult(
            state: SpfStates::FAIL,
            protocolStatus: \App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus::PERMERROR,
            riskStatus: \App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus::CRITICAL,
            summary: 'multiple',
            rawRecord: 'v=spf1 -all',
            normalizedRecord: 'v=spf1 -all',
            parsedTerms: [],
            parsedTerminalPolicy: null,
            terminalPolicy: \App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy::IMPLICIT_NEUTRAL,
            lookupCount: 0,
            lookupLimit: 10,
            lookupsRemaining: 10,
            voidLookupCount: 0,
            lookupPaths: [],
            recursiveDependencies: [],
            resolvedIps: [],
            flattenedRecord: null,
            errors: [['code' => 'MULTIPLE_SPF_RECORDS', 'message' => 'Multiple SPF records were found.']],
            warnings: [],
            resolverDiagnostics: [],
            discovery: ['source' => 'dns_collection', 'multiple_records' => true],
        );

        $dto = (new SpfLegacyPayloadAdapter())->toSpfResultDto($native);
        $this->assertContains(SpfResolver::WARNING_MULTIPLE_SPF, $dto->warnings);
    }

    public function test_check_registry_has_no_spf_specific_branches(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/CheckRegistry.php'));
        $this->assertStringNotContainsString('SpfCheck', $source);
        $this->assertStringNotContainsString('SpfResolver', $source);
        $this->assertStringNotContainsString('instanceof', $source);
    }
}
