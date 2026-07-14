<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Contracts\DnsCollectorInterface;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class FixtureLoader
{
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
                );
            }
        });
    }
}
