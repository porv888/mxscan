<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcOrganizationalDomainResolver;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcRecordDiscovery;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\Support\EmailSecurity\FakeDmarcDnsResolver;
use Tests\TestCase;

class DmarcOrganizationalDomainResolverTest extends TestCase
{
    public function test_exact_hit_uses_exact_policy_source(): void
    {
        $record = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com';
        $dns = $this->dnsDto('example.test', $record);
        $resolver = $this->resolverWithMap([
            '_dmarc.example.test' => $record,
        ]);

        $result = $this->resolver($resolver)->resolve('example.test', $dns);

        $this->assertSame('exact', $result['policy_source']);
        $this->assertSame('example.test', $result['policy_domain']);
    }

    public function test_tree_walk_finds_organizational_record(): void
    {
        $orgRecord = 'v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@b.com';
        $dns = $this->dnsDto('mail.example.test', null);
        $resolver = $this->resolverWithMap([
            '_dmarc.mail.example.test' => null,
            '_dmarc.example.test' => $orgRecord,
        ]);

        $result = $this->resolver($resolver)->resolve('mail.example.test', $dns);

        $this->assertSame('organizational', $result['policy_source']);
        $this->assertSame('example.test', $result['policy_domain']);
    }

    public function test_query_cap_is_enforced(): void
    {
        $dns = $this->dnsDto('a.b.c.d.e.f.example.test', null);
        $resolver = new FakeDmarcDnsResolver();

        $result = $this->resolver($resolver)->resolve('a.b.c.d.e.f.example.test', $dns);

        $this->assertLessThanOrEqual(DmarcOrganizationalDomainResolver::MAX_QUERIES, $result['queries_used']);
    }

    private function resolver(FakeDmarcDnsResolver $fake): DmarcOrganizationalDomainResolver
    {
        return new DmarcOrganizationalDomainResolver(
            new DmarcRecordDiscovery($fake),
            new DmarcParser(),
        );
    }

    /**
     * @param array<string, ?string> $map
     */
    private function resolverWithMap(array $map): FakeDmarcDnsResolver
    {
        $resolver = new FakeDmarcDnsResolver();
        foreach ($map as $hostname => $record) {
            $resolver->setRecord($hostname, $record);
        }

        return $resolver;
    }

    private function dnsDto(string $domain, ?string $record): DnsCollectionResultDTO
    {
        $payload = DmarcFixtureBuilder::dnsPayloadWithDmarc($domain, $record);

        return new DnsCollectionResultDTO(
            records: $payload['records'] ?? [],
            score: 0,
            scoreBreakdown: [],
            legacyDnsPayload: $payload,
            dmarcTxtRecords: $payload['dmarc_txt_records'] ?? [],
        );
    }
}
