<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;

final class MxTargetResolver
{
    public const STATUS_USABLE = 'usable';
    public const STATUS_USABLE_WITH_WARNINGS = 'usable_with_warnings';
    public const STATUS_DANGLING = 'dangling';
    public const STATUS_ALIAS_INVALID = 'alias_invalid';
    public const STATUS_INVALID_HOSTNAME = 'invalid_hostname';
    public const STATUS_TEMPORARY_DNS_FAILURE = 'temporary_dns_failure';
    public const STATUS_NON_PUBLIC_ONLY = 'non_public_only';
    public const STATUS_PARTIALLY_RESOLVED = 'partially_resolved';
    public const STATUS_NULL = 'null';

    public const MAX_CNAME_DEPTH = 8;

    public function __construct(
        private MxDnsResolverInterface $resolver,
        private MxAddressClassifier $addressClassifier,
    ) {
    }

    /**
     * @param array<string, mixed> $record
     * @return array<string, mixed>
     */
    public function resolve(array $record): array
    {
        $hostname = (string) ($record['normalized_exchange'] ?? '');

        if ($hostname === '.') {
            return $this->targetResult($record, self::STATUS_NULL, [], [], false, null, [], false, [], []);
        }

        if (($record['syntactically_valid'] ?? false) !== true) {
            return $this->targetResult($record, self::STATUS_INVALID_HOSTNAME, [], [], false, null, [], false, [[
                'code' => 'INVALID_HOSTNAME',
                'message' => 'MX exchange is not a valid hostname.',
            ]], []);
        }

        $aliasEvidence = $this->detectAlias($hostname);
        if ($aliasEvidence['is_alias']) {
            return $this->targetResult(
                $record,
                self::STATUS_ALIAS_INVALID,
                [],
                [],
                true,
                $aliasEvidence['alias_target'],
                $aliasEvidence['alias_path'],
                $aliasEvidence['alias_cycle'],
                [[
                    'code' => 'MX_TARGET_IS_CNAME',
                    'message' => 'The MX exchange hostname must not be a CNAME alias.',
                ]],
                [],
            );
        }

        $aQuery = $this->resolver->a($hostname);
        $aaaaQuery = $this->resolver->aaaa($hostname);

        if ($aQuery->isTemperror() && $aaaaQuery->isTemperror()) {
            return $this->targetResult($record, self::STATUS_TEMPORARY_DNS_FAILURE, [], [], false, null, [], false, [[
                'code' => 'TARGET_DNS_FAILURE',
                'message' => 'Temporary DNS failure prevented MX target evaluation.',
            ]], []);
        }

        $aAddresses = $this->classifyAddresses($aQuery->addresses);
        $aaaaAddresses = $this->classifyAddresses($aaaaQuery->addresses);
        $usableCount = $this->countUsable($aAddresses) + $this->countUsable($aaaaAddresses);
        $invalidCount = count($aAddresses) + count($aaaaAddresses) - $usableCount;
        $warnings = [];
        $errors = [];

        if ($aAddresses === [] && $aaaaAddresses === []) {
            return $this->targetResult($record, self::STATUS_DANGLING, $aAddresses, $aaaaAddresses, false, null, [], false, [[
                'code' => 'DANGLING_MX_TARGET',
                'message' => 'MX target does not resolve to any address records.',
            ]], $warnings);
        }

        if ($usableCount === 0) {
            return $this->targetResult($record, self::STATUS_NON_PUBLIC_ONLY, $aAddresses, $aaaaAddresses, false, null, [], false, [[
                'code' => 'NON_PUBLIC_MX_ADDRESS',
                'message' => 'MX target resolves only to non-public or invalid addresses.',
            ]], $warnings);
        }

        if ($invalidCount > 0) {
            $warnings[] = [
                'code' => 'MIXED_TARGET_ADDRESSES',
                'message' => 'MX target resolves to both usable and invalid addresses.',
            ];

            return $this->targetResult($record, self::STATUS_USABLE_WITH_WARNINGS, $aAddresses, $aaaaAddresses, false, null, [], false, $errors, $warnings, $usableCount);
        }

        if (($aQuery->isTemperror() && !$aaaaQuery->isTemperror() && $usableCount > 0)
            || ($aaaaQuery->isTemperror() && !$aQuery->isTemperror() && $usableCount > 0)) {
            $warnings[] = [
                'code' => 'PARTIAL_TARGET_RESOLUTION',
                'message' => 'One address record type could not be evaluated reliably.',
            ];

            return $this->targetResult($record, self::STATUS_PARTIALLY_RESOLVED, $aAddresses, $aaaaAddresses, false, null, [], false, $errors, $warnings, $usableCount);
        }

        return $this->targetResult($record, self::STATUS_USABLE, $aAddresses, $aaaaAddresses, false, null, [], false, $errors, $warnings, $usableCount);
    }

    /**
     * @return array{is_alias: bool, alias_target: ?string, alias_path: list<string>, alias_cycle: bool}
     */
    private function detectAlias(string $hostname): array
    {
        $path = [];
        $current = $hostname;

        for ($depth = 0; $depth < self::MAX_CNAME_DEPTH; $depth++) {
            if (in_array($current, $path, true)) {
                return [
                    'is_alias' => true,
                    'alias_target' => $current,
                    'alias_path' => $path,
                    'alias_cycle' => true,
                ];
            }

            $path[] = $current;
            $cnameQuery = $this->resolver->cname($current);

            if ($cnameQuery->isTemperror()) {
                return ['is_alias' => false, 'alias_target' => null, 'alias_path' => [], 'alias_cycle' => false];
            }

            if ($cnameQuery->cnameTargets === []) {
                return ['is_alias' => false, 'alias_target' => null, 'alias_path' => [], 'alias_cycle' => false];
            }

            return [
                'is_alias' => true,
                'alias_target' => $cnameQuery->cnameTargets[0],
                'alias_path' => $path,
                'alias_cycle' => false,
            ];
        }

        return [
            'is_alias' => true,
            'alias_target' => $current,
            'alias_path' => $path,
            'alias_cycle' => true,
        ];
    }

    /**
     * @param list<array<string, mixed>> $aAddresses
     * @param list<array<string, mixed>> $aaaaAddresses
     * @param list<string> $aliasPath
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @return array<string, mixed>
     */
    private function targetResult(
        array $record,
        string $status,
        array $aAddresses,
        array $aaaaAddresses,
        bool $isAlias,
        ?string $aliasTarget,
        array $aliasPath,
        bool $aliasCycle,
        array $errors,
        array $warnings,
        ?int $usableCount = null,
    ): array {
        $usableCount ??= $this->countUsable($aAddresses) + $this->countUsable($aaaaAddresses);

        return [
            'preference' => (int) ($record['preference'] ?? 0),
            'hostname' => (string) ($record['raw_exchange'] ?? $record['normalized_exchange'] ?? ''),
            'normalized_hostname' => (string) ($record['normalized_exchange'] ?? ''),
            'status' => $status,
            'is_alias' => $isAlias,
            'alias_target' => $aliasTarget,
            'alias_path' => $aliasPath,
            'alias_cycle' => $aliasCycle,
            'a_addresses' => $this->sanitizeAddresses($aAddresses),
            'aaaa_addresses' => $this->sanitizeAddresses($aaaaAddresses),
            'usable_address_count' => $usableCount,
            'errors' => $errors,
            'warnings' => $warnings,
        ];
    }

    /**
     * @param list<string> $addresses
     * @return list<array<string, mixed>>
     */
    private function classifyAddresses(array $addresses): array
    {
        return array_values(array_map(
            fn (string $address) => $this->addressClassifier->classify($address),
            $addresses,
        ));
    }

    /**
     * @param list<array<string, mixed>> $addresses
     */
    private function countUsable(array $addresses): int
    {
        return count(array_filter($addresses, fn (array $item) => ($item['usable'] ?? false) === true));
    }

    /**
     * @param list<array<string, mixed>> $addresses
     * @return list<array<string, mixed>>
     */
    private function sanitizeAddresses(array $addresses): array
    {
        return array_values(array_map(function (array $item): array {
            $classification = (string) ($item['classification'] ?? MxAddressClassifier::INVALID);

            if (($item['usable'] ?? false) === true) {
                return [
                    'address' => (string) ($item['address'] ?? ''),
                    'classification' => $classification,
                    'usable' => true,
                ];
            }

            return [
                'address' => (string) ($item['address'] ?? ''),
                'classification' => $classification,
                'usable' => false,
            ];
        }, $addresses));
    }
}
