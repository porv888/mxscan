<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorCandidate;
use App\Domain\EmailSecurity\Checks\DKIM\Discovery\DkimRecordDiscovery;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;
use PHPUnit\Framework\TestCase;

class DkimRecordDiscoveryTest extends TestCase
{
    public function test_does_not_call_end_on_readonly_cname_path(): void
    {
        $resolver = new class implements DkimDnsResolverInterface {
            public function txt(string $hostname): DkimDnsQueryResult
            {
                return new DkimDnsQueryResult(
                    hostname: $hostname,
                    success: true,
                    rawRows: [],
                    reconstructedTxt: ['v=DKIM1; p=abc'],
                    outcome: DkimDnsQueryResult::OUTCOME_ANSWER,
                    cnamePath: ['selector._domainkey.example.com', 'cdn.example.net'],
                    cnameTarget: null,
                );
            }

            public function reset(): void
            {
            }
        };

        $discovery = new DkimRecordDiscovery($resolver);
        $result = $discovery->discover(new DkimSelectorCandidate(
            selector: 's1',
            source: 'catalog',
            confidence: 'low',
            hostname: 's1._domainkey.example.com',
        ));

        $this->assertSame('cdn.example.net', $result->cnameTarget);
    }
}
