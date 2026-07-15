<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Evaluation;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistProviderDefinition;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistQueryOutcome;

final class BlacklistResponseInterpreter
{
    /**
     * @return array{outcome: string, interpreted_status: string, return_code: ?string, message: ?string}
     */
    public function interpret(BlacklistProviderDefinition $provider, BlacklistDnsQueryResult $dns): array
    {
        if (!$dns->success) {
            return $this->transportFailure($dns);
        }

        if ($dns->addresses === []) {
            if ($dns->dnsOutcome === 'NXDOMAIN' && $provider->nxdomainMeansClean) {
                return $this->result(BlacklistQueryOutcome::CLEAN_NXDOMAIN, 'clean', null, 'No listing returned (NXDOMAIN).');
            }

            if (in_array($dns->dnsOutcome, ['NOERROR', 'NO_DATA'], true) && $provider->noDataMeansClean) {
                return $this->result(BlacklistQueryOutcome::CLEAN_NO_DATA, 'clean', null, 'No listing returned.');
            }

            return $this->result(BlacklistQueryOutcome::UNKNOWN_ANSWER, 'unknown', null, 'Unexpected empty DNS response.');
        }

        foreach ($dns->addresses as $address) {
            if ($this->matchesCodes($address, $provider->blockedCodes)) {
                return $this->result(
                    BlacklistQueryOutcome::QUERY_BLOCKED,
                    'blocked',
                    $address,
                    'Provider blocked or refused the query.',
                );
            }

            if ($this->matchesCodes($address, $provider->rateLimitCodes)) {
                return $this->result(
                    BlacklistQueryOutcome::RATE_LIMITED,
                    'rate_limited',
                    $address,
                    'Provider rate-limited the query.',
                );
            }

            if ($this->matchesCodes($address, $provider->listingCodes)) {
                return $this->result(
                    BlacklistQueryOutcome::LISTED_ANSWER,
                    'listed',
                    $address,
                    'Listed on ' . $provider->name,
                );
            }
        }

        return $this->result(
            BlacklistQueryOutcome::UNKNOWN_ANSWER,
            'unknown',
            $dns->addresses[0] ?? null,
            'Unexpected provider response code.',
        );
    }

    /**
     * @return array{outcome: string, interpreted_status: string, return_code: ?string, message: ?string}
     */
    private function transportFailure(BlacklistDnsQueryResult $dns): array
    {
        $outcome = match ($dns->dnsOutcome) {
            'TIMEOUT' => BlacklistQueryOutcome::TIMEOUT,
            'SERVFAIL' => BlacklistQueryOutcome::SERVFAIL,
            'REFUSED' => BlacklistQueryOutcome::REFUSED,
            'MALFORMED' => BlacklistQueryOutcome::MALFORMED_RESPONSE,
            default => BlacklistQueryOutcome::PROVIDER_ERROR,
        };

        return $this->result($outcome, 'unavailable', null, $dns->error ?? 'Provider query failed.');
    }

    /**
     * @param list<string> $codes
     */
    private function matchesCodes(string $address, array $codes): bool
    {
        foreach ($codes as $code) {
            if (strcasecmp($address, $code) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{outcome: string, interpreted_status: string, return_code: ?string, message: ?string}
     */
    private function result(string $outcome, string $status, ?string $returnCode, ?string $message): array
    {
        return [
            'outcome' => $outcome,
            'interpreted_status' => $status,
            'return_code' => $returnCode,
            'message' => $message,
        ];
    }
}
