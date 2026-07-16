<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Evaluation;

use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;

final class DmarcExternalDestinationValidator
{
    public function __construct(
        private DmarcDnsResolverInterface $resolver,
    ) {
    }

    /**
     * @param list<array<string, mixed>> $destinations
     * @param string $policyDomain
     * @param string $organizationalDomain
     * @return array{destinations: list<array<string, mixed>>, unauthorized_count: int}
     */
    public function validateAggregateDestinations(
        array $destinations,
        string $policyDomain,
        string $organizationalDomain,
    ): array {
        $unauthorizedCount = 0;
        $validated = [];

        foreach ($destinations as $destination) {
            $email = (string) ($destination['normalized_destination'] ?? '');
            $domain = (string) ($destination['destination_domain'] ?? '');
            $internal = $this->isInternalDestination($domain, $policyDomain, $organizationalDomain);

            if ($internal) {
                $destination['internal'] = true;
                $destination['authorization_required'] = false;
                $destination['authorization_status'] = 'not_required';
                $validated[] = $destination;
                continue;
            }

            $lookupName = $policyDomain . '._report._dmarc.' . $domain;
            $query = $this->resolver->txt($lookupName);
            $destination['internal'] = false;
            $destination['authorization_required'] = true;
            $destination['authorization_lookup_name'] = $lookupName;

            if ($query->isTemperror()) {
                $destination['authorization_status'] = $query->outcome === DmarcDnsQueryResult::OUTCOME_TIMEOUT
                    ? 'dns_timeout'
                    : ($query->outcome === DmarcDnsQueryResult::OUTCOME_SERVFAIL ? 'servfail' : 'dns_error');
            } elseif ($this->hasAuthorizationRecord($query->reconstructedTxt)) {
                $destination['authorization_status'] = 'authorized';
            } else {
                $destination['authorization_status'] = 'unauthorized';
                $unauthorizedCount++;
            }

            $validated[] = $destination;
        }

        return [
            'destinations' => $validated,
            'unauthorized_count' => $unauthorizedCount,
        ];
    }

    private function isInternalDestination(string $destinationDomain, string $policyDomain, string $organizationalDomain): bool
    {
        $destinationDomain = strtolower($destinationDomain);

        return $destinationDomain === strtolower($policyDomain)
            || $destinationDomain === strtolower($organizationalDomain)
            || str_ends_with($destinationDomain, '.' . strtolower($organizationalDomain));
    }

    /**
     * @param list<string> $records
     */
    private function hasAuthorizationRecord(array $records): bool
    {
        foreach ($records as $record) {
            if (stripos(ltrim($record), 'v=DMARC1') === 0) {
                return true;
            }
        }

        return false;
    }
}
