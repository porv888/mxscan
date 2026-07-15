<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;
use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;
use App\Domain\EmailSecurity\Contracts\DnsCollectorInterface;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class FixtureLoader
{
    public const TEST_RSA_2048_DKIM_RECORD = 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArR8silhJEAglJVxFrnxaLj8PPqlZ+jnSsyIFYHHQNg0Z6PVHII9GcMXC2pVgLy3qTb+x7P2MjcAOg2vbLs94/btsR0ZE8meUyz6vUDe/DrawYEzcv2GVhEIsZL0MkEtBFxslIQQ3Z5DxsjS4z4E5O/bL//4OJrShGH5dcG/PIlYKtGhlo/2K+2OiFbGe1+lElhJp5s1E355xMv3y6my9ZMKmXxZJgpValYNhxNEy1+FPblSAUK4H/GXh7wFbJ6hRkQxCkfQeg7zi66e/D0gSpMwezbPqZvcVgxDy0Ug2M25B4BLs0uM77pYCKmd+I9Ccm2AWshqLa1Spehq/t23MdQIDAQAB';
    /**
     * @return array<string, mixed>
     */
    public static function input(string $name): array
    {
        $path = base_path("tests/Fixtures/EmailSecurity/inputs/{$name}.json");

        return json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<string, mixed>
     */
    public static function expected(string $path): array
    {
        $fullPath = base_path("tests/Fixtures/EmailSecurity/expected/{$path}.json");

        return json_decode((string) file_get_contents($fullPath), true, 512, JSON_THROW_ON_ERROR);
    }

    public static function dnsCollection(string $fixture = 'dns-bundled-full'): DnsCollectionResultDTO
    {
        $payload = self::input($fixture);

        return new DnsCollectionResultDTO(
            records: $payload['records'] ?? [],
            score: (int) ($payload['score'] ?? 0),
            scoreBreakdown: $payload['score_breakdown'] ?? [],
            legacyDnsPayload: $payload,
            rootTxtRecords: self::rootTxtRecordsFromPayload($payload),
            dmarcTxtRecords: self::dmarcTxtRecordsFromPayload($payload),
            mtaStsTxtRecords: self::mtaStsTxtRecordsFromPayload($payload),
            tlsRptTxtRecords: self::tlsRptTxtRecordsFromPayload($payload),
            bimiTxtRecords: self::bimiTxtRecordsFromPayload($payload),
        );
    }

    public static function bindDnsCollector(array $payload): void
    {
        app()->instance(DnsCollectorInterface::class, new class ($payload) implements DnsCollectorInterface {
            public function __construct(private array $payload)
            {
            }

            public function collect(string $domain): DnsCollectionResultDTO
            {
                return new DnsCollectionResultDTO(
                    records: $this->payload['records'] ?? [],
                    score: (int) ($this->payload['score'] ?? 0),
                    scoreBreakdown: $this->payload['score_breakdown'] ?? [],
                    legacyDnsPayload: $this->payload,
                    rootTxtRecords: FixtureLoader::rootTxtRecordsFromPayload($this->payload, $domain),
                    dmarcTxtRecords: FixtureLoader::dmarcTxtRecordsFromPayload($this->payload, $domain),
                    mtaStsTxtRecords: FixtureLoader::mtaStsTxtRecordsFromPayload($this->payload, $domain),
                    tlsRptTxtRecords: FixtureLoader::tlsRptTxtRecordsFromPayload($this->payload, $domain),
                    bimiTxtRecords: FixtureLoader::bimiTxtRecordsFromPayload($this->payload, $domain),
                );
            }
        });
    }

    public static function bindDkimResolver(string $domain = 'example.test'): void
    {
        $resolver = new DkimDnsMockResolver();

        foreach (['s1', 'google', 'selector1'] as $selector) {
            $hostname = "{$selector}._domainkey.{$domain}";
            $resolver->setTxt($hostname, new DkimDnsQueryResult(
                hostname: $hostname,
                success: true,
                reconstructedTxt: [self::TEST_RSA_2048_DKIM_RECORD],
                ttl: 3600,
                outcome: DkimDnsQueryResult::OUTCOME_ANSWER,
            ));
        }

        app()->instance(DkimDnsResolverInterface::class, $resolver);
    }

    /**
     * @param array<string, mixed> $payload
     * @return list<array{host: string, txt: string, ttl: ?int}>
     */
    public static function rootTxtRecordsFromPayload(array $payload, ?string $domain = 'example.test'): array
    {
        if (isset($payload['root_txt_records']) && is_array($payload['root_txt_records'])) {
            return $payload['root_txt_records'];
        }

        $spf = $payload['records']['SPF']['data'] ?? null;
        if (is_string($spf) && $spf !== '') {
            return [['host' => $domain ?? 'example.test', 'txt' => $spf, 'ttl' => 3600]];
        }

        return [];
    }

    /**
     * @param array<string, mixed> $payload
     * @return list<array{host: string, txt: string, ttl: ?int, rr_index: int}>
     */
    public static function dmarcTxtRecordsFromPayload(array $payload, ?string $domain = 'example.test'): array
    {
        if (isset($payload['dmarc_txt_records']) && is_array($payload['dmarc_txt_records'])) {
            return $payload['dmarc_txt_records'];
        }

        $dmarc = $payload['records']['DMARC']['data'] ?? null;
        if (is_string($dmarc) && $dmarc !== '' && ($payload['records']['DMARC']['status'] ?? '') === 'found') {
            return [[
                'host' => '_dmarc.' . ($domain ?? 'example.test'),
                'txt' => $dmarc,
                'ttl' => 3600,
                'rr_index' => 0,
            ]];
        }

        return [];
    }

    /**
     * @param array<string, mixed> $payload
     * @return list<array{host: string, txt: string, ttl: ?int, rr_index: int}>
     */
    public static function mtaStsTxtRecordsFromPayload(array $payload, ?string $domain = 'example.test'): array
    {
        if (isset($payload['mta_sts_txt_records']) && is_array($payload['mta_sts_txt_records'])) {
            return $payload['mta_sts_txt_records'];
        }

        $mtaSts = $payload['records']['MTA-STS']['data'] ?? null;
        if (is_string($mtaSts) && $mtaSts !== '' && ($payload['records']['MTA-STS']['status'] ?? '') === 'found') {
            return [[
                'host' => '_mta-sts.' . ($domain ?? 'example.test'),
                'txt' => $mtaSts,
                'ttl' => 3600,
                'rr_index' => 0,
            ]];
        }

        return [];
    }

    /**
     * @param array<string, mixed> $payload
     * @return list<array{host: string, txt: string, ttl: ?int, rr_index: int}>
     */
    public static function tlsRptTxtRecordsFromPayload(array $payload, ?string $domain = 'example.test'): array
    {
        if (isset($payload['tls_rpt_txt_records']) && is_array($payload['tls_rpt_txt_records'])) {
            return $payload['tls_rpt_txt_records'];
        }

        $tlsRpt = $payload['records']['TLS-RPT']['data'] ?? null;
        if (is_string($tlsRpt) && $tlsRpt !== '' && ($payload['records']['TLS-RPT']['status'] ?? '') === 'found') {
            return [[
                'host' => '_smtp._tls.' . ($domain ?? 'example.test'),
                'txt' => $tlsRpt,
                'ttl' => 3600,
                'rr_index' => 0,
            ]];
        }

        return [];
    }

    /**
     * @param array<string, mixed> $payload
     * @return list<array{host: string, txt: string, ttl: ?int, rr_index: int}>
     */
    public static function bimiTxtRecordsFromPayload(array $payload, ?string $domain = 'example.test'): array
    {
        if (isset($payload['bimi_txt_records']) && is_array($payload['bimi_txt_records'])) {
            return $payload['bimi_txt_records'];
        }

        return [];
    }

    public static function bindMtaStsFixtures(): void
    {
        app()->instance(
            \App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsDnsResolverInterface::class,
            new FakeMtaStsDnsResolver(),
        );
        app()->instance(
            \App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsHttpClientInterface::class,
            new FakeMtaStsHttpClient(),
        );
        CertificateTestProbeFactory::bindFakeProbes();
    }

    public static function bindTlsRptFixtures(): void
    {
        app()->instance(
            \App\Domain\EmailSecurity\Checks\TlsRpt\Contracts\TlsRptDnsResolverInterface::class,
            new FakeTlsRptDnsResolver(),
        );
    }

    public static function bindBimiFixtures(): void
    {
        app()->instance(
            \App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiDnsResolverInterface::class,
            new FakeBimiDnsResolver(),
        );
        app()->instance(
            \App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface::class,
            new class implements \App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface {
                public function fetch(string $url): array
                {
                    return [
                        'success' => false,
                        'url' => $url,
                        'http_status' => null,
                        'content_type' => null,
                        'body' => null,
                        'duration_ms' => 0,
                        'tls_verified' => false,
                        'error' => 'fixture_not_requested',
                        'failure_category' => 'fixture_not_requested',
                        'resolved_ips' => [],
                    ];
                }
            },
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function bindMxFixtures(array $payload, string $domain = 'example.test'): void
    {
        $resolver = new FakeMxDnsResolver();
        $mxBlock = $payload['records']['MX'] ?? null;

        if (is_array($mxBlock) && ($mxBlock['status'] ?? '') === 'found' && is_array($mxBlock['data'] ?? null)) {
            $records = [];
            foreach ($mxBlock['data'] as $row) {
                $records[] = [
                    'pri' => (int) ($row['pri'] ?? 0),
                    'target' => (string) ($row['target'] ?? ''),
                ];
            }
            $resolver->setMx($domain, $records);
            foreach ($records as $row) {
                $host = strtolower(rtrim($row['target'], '.'));
                if ($host !== '' && $host !== '.') {
                    $resolver->setA($host, ['8.8.8.8']);
                }
            }
        } else {
            $resolver->setMx($domain, []);
        }

        app()->instance(MxDnsResolverInterface::class, $resolver);
    }
}
