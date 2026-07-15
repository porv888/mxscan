<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

use App\Domain\EmailSecurity\Checks\Blacklist\Contracts\BlacklistDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistDnsQueryResult;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistIpv4QueryBuilder;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistIpv6QueryBuilder;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistResponseInterpreter;

final class BlacklistEvidenceBuilder
{
    public function __construct(
        private BlacklistProviderRegistry $registry,
        private BlacklistDnsResolverInterface $resolver,
        private BlacklistIpv4QueryBuilder $ipv4Builder,
        private BlacklistIpv6QueryBuilder $ipv6Builder,
        private BlacklistResponseInterpreter $interpreter,
    ) {
    }

    /**
     * @param list<BlacklistTarget> $targets
     * @return array{
     *   providers: list<array<string, mixed>>,
     *   checks: list<array<string, mixed>>,
     *   target_results: list<array<string, mixed>>,
     *   provider_health: list<array<string, mixed>>,
     *   listings: list<array<string, mixed>>,
     *   counts: array<string, int>,
     *   errors: list<array{code: string, message: string}>,
     *   warnings: list<array{code: string, message: string}>
     * }
     */
    public function build(array $targets): array
    {
        $providers = $this->registry->enabled();
        $concurrency = (int) config('rbl.query.concurrency', 20);
        $maxQueries = (int) config('rbl.query.max_queries', 500);
        $maxDurationMs = (int) config('rbl.query.max_duration_ms', 30000);
        $started = hrtime(true);

        $jobs = [];
        foreach ($targets as $target) {
            foreach ($providers as $provider) {
                $zone = $provider->zoneForVersion($target->version);
                if ($zone === null) {
                    continue;
                }

                $queryHost = $target->version === 4
                    ? $this->ipv4Builder->build($target->address, $zone)
                    : $this->ipv6Builder->build($target->address, $zone);

                if ($queryHost === null) {
                    continue;
                }

                $jobs[] = [
                    'target' => $target,
                    'provider' => $provider,
                    'query_host' => $queryHost,
                ];
            }
        }

        if (count($jobs) > $maxQueries) {
            $jobs = array_slice($jobs, 0, $maxQueries);
        }

        /** @var array<string, array<string, mixed>> $cache */
        $cache = [];
        $checks = [];

        foreach (array_chunk($jobs, max(1, $concurrency)) as $batch) {
            if (((hrtime(true) - $started) / 1_000_000) >= $maxDurationMs) {
                break;
            }

            foreach ($batch as $job) {
                $cacheKey = $job['target']->cacheKey() . '|' . $job['provider']->key;
                if (isset($cache[$cacheKey])) {
                    $checks[] = $cache[$cacheKey];
                    continue;
                }

                $dns = $this->queryWithRetries($job['provider'], $job['query_host']);
                $interpreted = $this->interpreter->interpret($job['provider'], $dns);

                $row = [
                    'target' => $job['target']->address,
                    'target_type' => $job['target']->version === 4 ? 'ipv4' : 'ipv6',
                    'source_mx_hostnames' => $job['target']->sourceHostnames,
                    'source_type' => $job['target']->sourceType,
                    'provider_key' => $job['provider']->key,
                    'provider_name' => $job['provider']->name,
                    'query_hostname' => $job['query_host'],
                    'dns_outcome' => $dns->dnsOutcome,
                    'response_addresses' => $dns->addresses,
                    'txt_evidence' => $dns->txtRecords,
                    'ttl' => $dns->ttl,
                    'duration_ms' => $dns->durationMs,
                    'retry_count' => $dns->retryCount,
                    'outcome' => $interpreted['outcome'],
                    'interpreted_status' => $interpreted['interpreted_status'],
                    'return_code' => $interpreted['return_code'],
                    'message' => $interpreted['message'],
                    'errors' => $dns->error !== null ? [$dns->error] : [],
                    'warnings' => [],
                ];

                $cache[$cacheKey] = $row;
                $checks[] = $row;
            }
        }

        return $this->aggregate($targets, $providers, $checks);
    }

    private function queryWithRetries(BlacklistProviderDefinition $provider, string $queryHost): BlacklistDnsQueryResult
    {
        $attempts = max(1, $provider->maxRetries + 1);
        $last = null;

        for ($i = 0; $i < $attempts; $i++) {
            $last = $this->resolver->queryA($queryHost, $provider->timeoutMs);
            if ($last->success && $last->addresses !== []) {
                return new BlacklistDnsQueryResult(
                    queryHost: $last->queryHost,
                    success: $last->success,
                    dnsOutcome: $last->dnsOutcome,
                    addresses: $last->addresses,
                    txtRecords: $last->txtRecords,
                    ttl: $last->ttl,
                    durationMs: $last->durationMs,
                    retryCount: $i,
                    error: $last->error,
                    httpCode: $last->httpCode,
                );
            }

            if ($last->success && in_array($last->dnsOutcome, ['NXDOMAIN', 'NO_DATA', 'ANSWER'], true)) {
                return new BlacklistDnsQueryResult(
                    queryHost: $last->queryHost,
                    success: $last->success,
                    dnsOutcome: $last->dnsOutcome,
                    addresses: $last->addresses,
                    txtRecords: $last->txtRecords,
                    ttl: $last->ttl,
                    durationMs: $last->durationMs,
                    retryCount: $i,
                    error: $last->error,
                    httpCode: $last->httpCode,
                );
            }

            if ($i + 1 < $attempts) {
                usleep(50_000);
            }
        }

        return $last ?? new BlacklistDnsQueryResult(
            queryHost: $queryHost,
            success: false,
            dnsOutcome: 'PROVIDER_ERROR',
            error: 'Query failed.',
        );
    }

    /**
     * @param list<BlacklistTarget> $targets
     * @param list<BlacklistProviderDefinition> $providers
     * @param list<array<string, mixed>> $checks
     * @return array{
     *   providers: list<array<string, mixed>>,
     *   checks: list<array<string, mixed>>,
     *   target_results: list<array<string, mixed>>,
     *   provider_health: list<array<string, mixed>>,
     *   listings: list<array<string, mixed>>,
     *   counts: array<string, int>,
     *   errors: list<array{code: string, message: string}>,
     *   warnings: list<array{code: string, message: string}>
     * }
     */
    private function aggregate(array $targets, array $providers, array $checks): array
    {
        $counts = [
            'targets_total' => count($targets),
            'ipv4_targets' => count(array_filter($targets, fn (BlacklistTarget $t) => $t->version === 4)),
            'ipv6_targets' => count(array_filter($targets, fn (BlacklistTarget $t) => $t->version === 6)),
            'domain_targets' => 0,
            'providers_enabled' => count($providers),
            'providers_compatible' => count($providers),
            'queries_planned' => count($checks),
            'queries_completed' => count($checks),
            'usable_results' => 0,
            'clean_results' => 0,
            'listed_results' => 0,
            'unknown_results' => 0,
            'blocked_results' => 0,
            'timeout_results' => 0,
            'skipped_results' => 0,
        ];

        $listings = [];
        $providerHealth = [];
        $targetResults = [];

        foreach ($checks as $check) {
            $outcome = (string) ($check['outcome'] ?? '');
            if (BlacklistQueryOutcome::isUsable($outcome)) {
                $counts['usable_results']++;
                if (BlacklistQueryOutcome::isClean($outcome)) {
                    $counts['clean_results']++;
                }
                if (BlacklistQueryOutcome::isListed($outcome)) {
                    $counts['listed_results']++;
                    $listings[] = $check;
                }
            } elseif ($outcome === BlacklistQueryOutcome::QUERY_BLOCKED) {
                $counts['blocked_results']++;
                $counts['unknown_results']++;
            } elseif ($outcome === BlacklistQueryOutcome::TIMEOUT) {
                $counts['timeout_results']++;
                $counts['unknown_results']++;
            } elseif (in_array($outcome, BlacklistQueryOutcome::unavailableOutcomes(), true)) {
                $counts['unknown_results']++;
            } elseif ($outcome === BlacklistQueryOutcome::SKIPPED) {
                $counts['skipped_results']++;
            } else {
                $counts['unknown_results']++;
            }

            $providerKey = (string) ($check['provider_key'] ?? '');
            if (!isset($providerHealth[$providerKey])) {
                $providerHealth[$providerKey] = [
                    'provider_key' => $providerKey,
                    'provider_name' => $check['provider_name'] ?? $providerKey,
                    'usable' => 0,
                    'unavailable' => 0,
                    'listed' => 0,
                ];
            }
            if (BlacklistQueryOutcome::isUsable($outcome)) {
                $providerHealth[$providerKey]['usable']++;
            } else {
                $providerHealth[$providerKey]['unavailable']++;
            }
            if (BlacklistQueryOutcome::isListed($outcome)) {
                $providerHealth[$providerKey]['listed']++;
            }

            $targetKey = (string) ($check['target'] ?? '');
            if (!isset($targetResults[$targetKey])) {
                $targetResults[$targetKey] = [
                    'target' => $targetKey,
                    'target_type' => $check['target_type'] ?? 'ipv4',
                    'source_mx_hostnames' => $check['source_mx_hostnames'] ?? [],
                    'listed_providers' => [],
                    'usable_checks' => 0,
                    'unavailable_checks' => 0,
                ];
            }
            if (BlacklistQueryOutcome::isUsable($outcome)) {
                $targetResults[$targetKey]['usable_checks']++;
            } else {
                $targetResults[$targetKey]['unavailable_checks']++;
            }
            if (BlacklistQueryOutcome::isListed($outcome)) {
                $targetResults[$targetKey]['listed_providers'][] = $providerKey;
            }
        }

        $providerRows = array_map(fn (BlacklistProviderDefinition $p) => [
            'key' => $p->key,
            'name' => $p->name,
            'enabled' => $p->enabled,
            'target_types' => $p->targetTypes,
            'zone' => $p->zone,
        ], $providers);

        return [
            'providers' => $providerRows,
            'checks' => $checks,
            'target_results' => array_values($targetResults),
            'provider_health' => array_values($providerHealth),
            'listings' => $listings,
            'counts' => $counts,
            'errors' => [],
            'warnings' => [],
        ];
    }
}
