<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use Tests\Support\EmailSecurity\FakeDnsClient;
use Tests\TestCase;

class SpfRecordDiscoveryTest extends TestCase
{
    public function test_selects_record_starting_with_v_spf1(): void
    {
        $this->assertTrue(SpfRecordDiscovery::isSpfRecord('v=spf1 -all'));
        $this->assertTrue(SpfRecordDiscovery::isSpfRecord('V=SPF1 -all'));
    }

    public function test_rejects_v_spf10(): void
    {
        $this->assertFalse(SpfRecordDiscovery::isSpfRecord('v=spf10 -all'));
    }

    public function test_rejects_embedded_version_token(): void
    {
        $this->assertFalse(SpfRecordDiscovery::isSpfRecord('prefix v=spf1 -all'));
    }

    public function test_discovers_from_dns_collection(): void
    {
        $resolver = new SpfDnsDependencyResolver(new FakeDnsClient());
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
    }

    public function test_detects_multiple_spf_records(): void
    {
        $resolver = new SpfDnsDependencyResolver(new FakeDnsClient());
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

    public function test_joins_txt_chunks_without_spaces(): void
    {
        $joined = SpfRecordDiscovery::joinTxtChunks(['v=spf1', ' include:example.com ', '-all']);
        $this->assertSame('v=spf1 include:example.com -all', $joined);
    }
}
