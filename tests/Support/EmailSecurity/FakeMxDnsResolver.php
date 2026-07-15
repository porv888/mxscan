<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxDnsQueryResult;

final class FakeMxDnsResolver implements MxDnsResolverInterface
{
    /** @var array<string, MxDnsQueryResult> */
    private array $responses = [];

    public function setResponse(string $key, MxDnsQueryResult $result): void
    {
        $this->responses[$key] = $result;
    }

    public function mx(string $domain): MxDnsQueryResult
    {
        return $this->responses['MX:' . strtolower(rtrim($domain, '.'))]
            ?? new MxDnsQueryResult($domain, true, outcome: MxDnsQueryResult::OUTCOME_NO_DATA);
    }

    public function a(string $hostname): MxDnsQueryResult
    {
        return $this->responses['A:' . strtolower(rtrim($hostname, '.'))]
            ?? new MxDnsQueryResult($hostname, true, outcome: MxDnsQueryResult::OUTCOME_NO_DATA);
    }

    public function aaaa(string $hostname): MxDnsQueryResult
    {
        return $this->responses['AAAA:' . strtolower(rtrim($hostname, '.'))]
            ?? new MxDnsQueryResult($hostname, true, outcome: MxDnsQueryResult::OUTCOME_NO_DATA);
    }

    public function cname(string $hostname): MxDnsQueryResult
    {
        return $this->responses['CNAME:' . strtolower(rtrim($hostname, '.'))]
            ?? new MxDnsQueryResult($hostname, true, outcome: MxDnsQueryResult::OUTCOME_NO_DATA);
    }

    /**
     * @param list<array{pri: int, target: string}> $records
     */
    public function setMx(string $domain, array $records, string $outcome = MxDnsQueryResult::OUTCOME_ANSWER): void
    {
        if ($records === []) {
            $this->setResponse('MX:' . strtolower(rtrim($domain, '.')), new MxDnsQueryResult(
                hostname: strtolower(rtrim($domain, '.')),
                success: true,
                outcome: MxDnsQueryResult::OUTCOME_NO_DATA,
            ));

            return;
        }

        $rawRows = [];
        foreach ($records as $index => $record) {
            $rawRows[] = [
                'pri' => $record['pri'],
                'target' => $record['target'],
                'ttl' => 300,
            ];
        }

        $this->setResponse('MX:' . strtolower(rtrim($domain, '.')), new MxDnsQueryResult(
            hostname: strtolower(rtrim($domain, '.')),
            success: true,
            rawRows: $rawRows,
            addresses: array_column($records, 'target'),
            ttl: 300,
            outcome: $outcome,
        ));
    }

    /**
     * @param list<string> $addresses
     */
    public function setA(string $hostname, array $addresses): void
    {
        $rawRows = array_map(fn (string $ip) => ['ip' => $ip, 'ttl' => 300], $addresses);
        $this->setResponse('A:' . strtolower(rtrim($hostname, '.')), new MxDnsQueryResult(
            hostname: strtolower(rtrim($hostname, '.')),
            success: true,
            rawRows: $rawRows,
            addresses: $addresses,
            ttl: 300,
            outcome: $addresses === [] ? MxDnsQueryResult::OUTCOME_NO_DATA : MxDnsQueryResult::OUTCOME_ANSWER,
        ));
    }

    /**
     * @param list<string> $addresses
     */
    public function setAaaa(string $hostname, array $addresses): void
    {
        $rawRows = array_map(fn (string $ip) => ['ipv6' => $ip, 'ttl' => 300], $addresses);
        $this->setResponse('AAAA:' . strtolower(rtrim($hostname, '.')), new MxDnsQueryResult(
            hostname: strtolower(rtrim($hostname, '.')),
            success: true,
            rawRows: $rawRows,
            addresses: $addresses,
            ttl: 300,
            outcome: $addresses === [] ? MxDnsQueryResult::OUTCOME_NO_DATA : MxDnsQueryResult::OUTCOME_ANSWER,
        ));
    }

    public function setCname(string $hostname, string $target): void
    {
        $this->setResponse('CNAME:' . strtolower(rtrim($hostname, '.')), new MxDnsQueryResult(
            hostname: strtolower(rtrim($hostname, '.')),
            success: true,
            rawRows: [['target' => $target, 'ttl' => 300]],
            cnameTargets: [strtolower(rtrim($target, '.'))],
            ttl: 300,
            outcome: MxDnsQueryResult::OUTCOME_ANSWER,
        ));
    }
}
