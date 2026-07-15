<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

use InvalidArgumentException;

final class BlacklistProviderRegistry
{
    /** @var array<string, BlacklistProviderDefinition> */
    private array $providers = [];

    public function __construct()
    {
        $this->loadFromConfig();
        $this->validate();
    }

    /**
     * @return list<BlacklistProviderDefinition>
     */
    public function enabled(): array
    {
        return array_values(array_filter($this->providers, fn (BlacklistProviderDefinition $p) => $p->enabled));
    }

    /**
     * @return list<BlacklistProviderDefinition>
     */
    public function all(): array
    {
        return array_values($this->providers);
    }

    public function get(string $key): ?BlacklistProviderDefinition
    {
        return $this->providers[$key] ?? null;
    }

    private function loadFromConfig(): void
    {
        $configured = config('rbl.providers', []);
        foreach ($configured as $key => $row) {
            $listingCodes = array_values($row['listing_codes'] ?? []);
            $blockedCodes = array_values($row['blocked_codes'] ?? []);
            $rateLimitCodes = array_values($row['rate_limit_codes'] ?? []);

            $this->providers[$key] = new BlacklistProviderDefinition(
                key: (string) $key,
                name: (string) ($row['name'] ?? $key),
                zone: (string) ($row['zone'] ?? $row['host'] ?? ''),
                ipv6Zone: isset($row['ipv6_zone']) ? (string) $row['ipv6_zone'] : null,
                enabled: (bool) ($row['enabled'] ?? false),
                targetTypes: array_values($row['target_types'] ?? ['ipv4']),
                interpreter: (string) ($row['interpreter'] ?? 'standard_ipv4'),
                listingCodes: $listingCodes,
                blockedCodes: $blockedCodes,
                rateLimitCodes: $rateLimitCodes,
                nxdomainMeansClean: (bool) ($row['nxdomain_means_clean'] ?? true),
                noDataMeansClean: (bool) ($row['no_data_means_clean'] ?? true),
                timeoutMs: (int) ($row['timeout_ms'] ?? config('rbl.query.timeout_ms', 3000)),
                maxRetries: (int) ($row['max_retries'] ?? config('rbl.query.max_retries', 1)),
                delistUrl: (string) ($row['delist_url'] ?? ''),
                metadata: is_array($row['metadata'] ?? null) ? $row['metadata'] : [],
            );
        }
    }

    private function validate(): void
    {
        $keys = [];
        foreach ($this->providers as $provider) {
            if (isset($keys[$provider->key])) {
                throw new InvalidArgumentException('Duplicate blacklist provider key: ' . $provider->key);
            }
            $keys[$provider->key] = true;

            if ($provider->zone === '' && $provider->enabled) {
                throw new InvalidArgumentException('Enabled provider missing zone: ' . $provider->key);
            }

            if ($provider->targetTypes === [] && $provider->enabled) {
                throw new InvalidArgumentException('Enabled provider missing target types: ' . $provider->key);
            }

            if ($provider->listingCodes === [] && $provider->enabled) {
                throw new InvalidArgumentException('Enabled provider missing listing codes: ' . $provider->key);
            }

            $overlap = array_intersect($provider->listingCodes, $provider->blockedCodes);
            if ($overlap !== []) {
                throw new InvalidArgumentException('Provider listing/blocked code overlap: ' . $provider->key);
            }
        }
    }
}
