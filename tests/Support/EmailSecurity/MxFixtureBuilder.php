<?php

namespace Tests\Support\EmailSecurity;

final class MxFixtureBuilder
{
    /**
     * @param list<array{pri: int, target: string, ttl?: int}>|null $mxData
     * @return array<string, mixed>
     */
    public static function dnsPayload(string $domain, ?array $mxData, string $status = 'found'): array
    {
        $payload = FixtureLoader::input('dns-bundled-full');

        if ($mxData === null || $mxData === []) {
            $payload['records']['MX'] = ['status' => 'missing'];
        } else {
            $rows = [];
            foreach ($mxData as $row) {
                $rows[] = [
                    'pri' => (int) ($row['pri'] ?? 0),
                    'target' => (string) ($row['target'] ?? ''),
                    'ttl' => (int) ($row['ttl'] ?? 3600),
                ];
            }
            $payload['records']['MX'] = ['status' => $status, 'data' => $rows];
        }

        return $payload;
    }

    /**
     * @param list<array{pri: int, target: string}> $mxRecords
     */
    public static function bindHealthyTargets(FakeMxDnsResolver $resolver, string $domain, array $mxRecords): void
    {
        $resolver->setMx($domain, $mxRecords);

        foreach ($mxRecords as $row) {
            $host = strtolower(rtrim((string) ($row['target'] ?? ''), '.'));
            if ($host !== '' && $host !== '.') {
                $resolver->setA($host, ['8.8.8.8']);
            }
        }
    }

    public static function mxRow(int $pri, string $target): array
    {
        return ['pri' => $pri, 'target' => $target];
    }
}
