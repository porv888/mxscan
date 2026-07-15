<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;

final class MxImplicitFallbackEvaluator
{
    public function __construct(
        private MxDnsResolverInterface $resolver,
        private MxAddressClassifier $addressClassifier,
    ) {
    }

    /**
     * @return array{evaluated: bool, active: bool, reason: ?string, a_addresses: list<array<string, mixed>>, aaaa_addresses: list<array<string, mixed>>, usable_address_count: int, invalid_address_count: int, dns_failure: bool}
     */
    public function evaluate(string $domain): array
    {
        $aQuery = $this->resolver->a($domain);
        $aaaaQuery = $this->resolver->aaaa($domain);

        if ($aQuery->isTemperror() || $aaaaQuery->isTemperror()) {
            return [
                'evaluated' => true,
                'active' => false,
                'reason' => 'temporary_dns_failure',
                'a_addresses' => [],
                'aaaa_addresses' => [],
                'usable_address_count' => 0,
                'invalid_address_count' => 0,
                'dns_failure' => true,
            ];
        }

        $aAddresses = $this->classifyAddresses($aQuery->addresses);
        $aaaaAddresses = $this->classifyAddresses($aaaaQuery->addresses);
        $usableCount = $this->countUsable($aAddresses) + $this->countUsable($aaaaAddresses);
        $invalidCount = count($aAddresses) + count($aaaaAddresses) - $usableCount;

        return [
            'evaluated' => true,
            'active' => $usableCount > 0,
            'reason' => $usableCount > 0 ? 'usable_apex_addresses' : 'no_usable_apex_addresses',
            'a_addresses' => $aAddresses,
            'aaaa_addresses' => $aaaaAddresses,
            'usable_address_count' => $usableCount,
            'invalid_address_count' => $invalidCount,
            'dns_failure' => false,
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
}
