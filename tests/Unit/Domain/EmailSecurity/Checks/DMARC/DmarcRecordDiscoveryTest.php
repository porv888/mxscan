<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcRecordDiscovery;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\Support\EmailSecurity\FakeDmarcDnsResolver;
use Tests\TestCase;

class DmarcRecordDiscoveryTest extends TestCase
{
    public function test_evidence_first_skips_resolver_when_dmarc_txt_records_present(): void
    {
        $record = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com';
        $dns = new DnsCollectionResultDTO(
            records: ['DMARC' => ['status' => 'found', 'data' => $record]],
            score: 0,
            scoreBreakdown: [],
            legacyDnsPayload: [],
            dmarcTxtRecords: DmarcFixtureBuilder::txtEvidence('example.test', $record),
        );
        $resolver = new FakeDmarcDnsResolver();

        $discovery = new DmarcRecordDiscovery($resolver);
        $result = $discovery->discoverAtHostname('example.test', '_dmarc.example.test', $dns);

        $this->assertSame($record, $result->record);
        $this->assertSame('dns_collection', $result->source);
        $this->assertSame('no stubbed response', $resolver->txt('_dmarc.example.test')->error);
    }

    public function test_empty_evidence_calls_resolver(): void
    {
        $record = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com';
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setRecord('_dmarc.example.test', $record);

        $discovery = new DmarcRecordDiscovery($resolver);
        $result = $discovery->discoverAtHostname('example.test', '_dmarc.example.test', null);

        $this->assertSame($record, $result->record);
        $this->assertSame('dns_query', $result->source);
    }
}
