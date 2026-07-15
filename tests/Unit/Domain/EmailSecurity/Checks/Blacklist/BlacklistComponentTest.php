<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\Blacklist;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistAnalysisStatus;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistProviderRegistry;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistQueryOutcome;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistReputationStatus;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistStates;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistStatusDeriver;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistDnsQueryResult;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistIpv4QueryBuilder;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistIpv6QueryBuilder;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistResponseInterpreter;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistProviderDefinition;
use Tests\TestCase;

class BlacklistComponentTest extends TestCase
{
    public function test_ipv4_reverse_query(): void
    {
        $builder = new BlacklistIpv4QueryBuilder();
        $this->assertSame('50.113.0.203.zen.spamhaus.org', $builder->build('203.0.113.50', 'zen.spamhaus.org'));
    }

    public function test_ipv6_nibble_reverse(): void
    {
        $builder = new BlacklistIpv6QueryBuilder();
        $query = $builder->build('2001:db8::1', 'zen.spamhaus.org');
        $this->assertNotNull($query);
        $this->assertStringEndsWith('.zen.spamhaus.org', $query);
        $this->assertStringStartsWith('1.', $query);
    }

    public function test_invalid_targets_rejected(): void
    {
        $builder = new BlacklistIpv4QueryBuilder();
        $this->assertNull($builder->build('not-an-ip', 'zen.spamhaus.org'));
    }

    public function test_spamhaus_confirmed_listing(): void
    {
        $interpreter = new BlacklistResponseInterpreter();
        $provider = $this->spamhausProvider();
        $result = $interpreter->interpret($provider, new BlacklistDnsQueryResult(
            queryHost: '1.0.0.1.zen.spamhaus.org',
            success: true,
            dnsOutcome: 'ANSWER',
            addresses: ['127.0.0.2'],
        ));

        $this->assertSame(BlacklistQueryOutcome::LISTED_ANSWER, $result['outcome']);
    }

    public function test_spamhaus_blocked_response_not_listed(): void
    {
        $interpreter = new BlacklistResponseInterpreter();
        $provider = $this->spamhausProvider();
        $result = $interpreter->interpret($provider, new BlacklistDnsQueryResult(
            queryHost: '1.0.0.1.zen.spamhaus.org',
            success: true,
            dnsOutcome: 'ANSWER',
            addresses: ['127.255.255.254'],
        ));

        $this->assertSame(BlacklistQueryOutcome::QUERY_BLOCKED, $result['outcome']);
    }

    public function test_provider_defined_nxdomain_clean(): void
    {
        $interpreter = new BlacklistResponseInterpreter();
        $provider = $this->spamhausProvider();
        $result = $interpreter->interpret($provider, new BlacklistDnsQueryResult(
            queryHost: '1.0.0.1.zen.spamhaus.org',
            success: true,
            dnsOutcome: 'NXDOMAIN',
        ));

        $this->assertSame(BlacklistQueryOutcome::CLEAN_NXDOMAIN, $result['outcome']);
    }

    public function test_timeout_unavailable(): void
    {
        $interpreter = new BlacklistResponseInterpreter();
        $provider = $this->spamhausProvider();
        $result = $interpreter->interpret($provider, new BlacklistDnsQueryResult(
            queryHost: '1.0.0.1.zen.spamhaus.org',
            success: false,
            dnsOutcome: 'TIMEOUT',
        ));

        $this->assertSame(BlacklistQueryOutcome::TIMEOUT, $result['outcome']);
    }

    public function test_unexpected_answer_unknown(): void
    {
        $interpreter = new BlacklistResponseInterpreter();
        $provider = $this->spamhausProvider();
        $result = $interpreter->interpret($provider, new BlacklistDnsQueryResult(
            queryHost: '1.0.0.1.zen.spamhaus.org',
            success: true,
            dnsOutcome: 'ANSWER',
            addresses: ['127.0.0.99'],
        ));

        $this->assertSame(BlacklistQueryOutcome::UNKNOWN_ANSWER, $result['outcome']);
    }

    public function test_complete_clean_state(): void
    {
        $deriver = new BlacklistStatusDeriver();
        $derived = $deriver->derive([
            'queries_planned' => 6,
            'usable_results' => 6,
            'listed_results' => 0,
            'unknown_results' => 0,
            'clean_results' => 6,
        ], []);

        $this->assertSame(BlacklistReputationStatus::CLEAN, $derived['reputation_status']);
        $this->assertSame(BlacklistStates::PASS, $derived['state']);
        $this->assertSame(BlacklistAnalysisStatus::COMPLETE, $derived['analysis_status']);
    }

    public function test_partial_result_state(): void
    {
        $deriver = new BlacklistStatusDeriver();
        $derived = $deriver->derive([
            'queries_planned' => 6,
            'usable_results' => 3,
            'listed_results' => 0,
            'unknown_results' => 3,
            'clean_results' => 3,
        ], []);

        $this->assertSame(BlacklistReputationStatus::PARTIAL, $derived['reputation_status']);
        $this->assertSame(BlacklistStates::WARNING, $derived['state']);
    }

    public function test_all_unavailable_state(): void
    {
        $deriver = new BlacklistStatusDeriver();
        $derived = $deriver->derive([
            'queries_planned' => 6,
            'usable_results' => 0,
            'listed_results' => 0,
            'unknown_results' => 6,
        ], []);

        $this->assertSame(BlacklistReputationStatus::UNKNOWN, $derived['reputation_status']);
        $this->assertSame(BlacklistStates::UNKNOWN, $derived['state']);
    }

    public function test_confirmed_listing_state(): void
    {
        $deriver = new BlacklistStatusDeriver();
        $derived = $deriver->derive([
            'queries_planned' => 6,
            'usable_results' => 2,
            'listed_results' => 1,
            'unknown_results' => 4,
        ], [['provider_key' => 'spamhaus_zen']]);

        $this->assertSame(BlacklistReputationStatus::LISTED, $derived['reputation_status']);
        $this->assertSame(BlacklistStates::FAIL, $derived['state']);
    }

    public function test_zero_planned_never_clean(): void
    {
        $deriver = new BlacklistStatusDeriver();
        $derived = $deriver->derive([
            'queries_planned' => 0,
            'usable_results' => 0,
            'listed_results' => 0,
        ], [], 'No targets');

        $this->assertNotSame(BlacklistReputationStatus::CLEAN, $derived['reputation_status']);
    }

    public function test_provider_registry_validates_enabled_providers(): void
    {
        $registry = new BlacklistProviderRegistry();
        $enabled = $registry->enabled();
        $this->assertNotEmpty($enabled);
        foreach ($enabled as $provider) {
            $this->assertNotSame('', $provider->zone);
            $this->assertNotEmpty($provider->listingCodes);
        }
    }

    private function spamhausProvider(): BlacklistProviderDefinition
    {
        return new BlacklistProviderDefinition(
            key: 'spamhaus_zen',
            name: 'Spamhaus ZEN',
            zone: 'zen.spamhaus.org',
            ipv6Zone: 'zen.spamhaus.org',
            enabled: true,
            targetTypes: ['ipv4', 'ipv6'],
            interpreter: 'spamhaus_zen',
            listingCodes: ['127.0.0.2', '127.0.0.3'],
            blockedCodes: ['127.255.255.254'],
            rateLimitCodes: [],
            nxdomainMeansClean: true,
            noDataMeansClean: true,
            timeoutMs: 3000,
            maxRetries: 1,
            delistUrl: 'https://check.spamhaus.org/',
        );
    }
}
