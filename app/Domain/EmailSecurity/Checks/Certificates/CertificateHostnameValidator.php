<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateParsedFields;

final class CertificateHostnameValidator
{
    /**
     * @return array{hostname_match: bool, matched_identity: ?string, mismatch_reason: ?string}
     */
    public function validate(string $requestedHostname, CertificateParsedFields $parsed): array
    {
        $requested = CertificateEndpoint::normalizeHostname($requestedHostname);

        if ($requested === '') {
            return [
                'hostname_match' => false,
                'matched_identity' => null,
                'mismatch_reason' => 'Requested hostname is empty.',
            ];
        }

        if (filter_var($requested, FILTER_VALIDATE_IP) !== false) {
            return $this->matchIpAddress($requested, $parsed);
        }

        if ($parsed->sanDns !== []) {
            foreach ($parsed->sanDns as $san) {
                $match = $this->matchDnsName($requested, $san);
                if ($match['matched']) {
                    return [
                        'hostname_match' => true,
                        'matched_identity' => $match['identity'],
                        'mismatch_reason' => null,
                    ];
                }
            }
        }

        if ($parsed->commonName !== null && $parsed->commonName !== '') {
            $match = $this->matchDnsName($requested, $parsed->commonName);
            if ($match['matched']) {
                return [
                    'hostname_match' => true,
                    'matched_identity' => $match['identity'],
                    'mismatch_reason' => null,
                ];
            }
        }

        return [
            'hostname_match' => false,
            'matched_identity' => null,
            'mismatch_reason' => 'Certificate identity does not match requested hostname.',
        ];
    }

    /**
     * @return array{hostname_match: bool, matched_identity: ?string, mismatch_reason: ?string}
     */
    private function matchIpAddress(string $requestedIp, CertificateParsedFields $parsed): array
    {
        foreach ($parsed->sanIp as $sanIp) {
            if (strcasecmp($requestedIp, $sanIp) === 0) {
                return [
                    'hostname_match' => true,
                    'matched_identity' => $sanIp,
                    'mismatch_reason' => null,
                ];
            }
        }

        return [
            'hostname_match' => false,
            'matched_identity' => null,
            'mismatch_reason' => 'Certificate does not contain a matching IP SAN entry.',
        ];
    }

    /**
     * @return array{matched: bool, identity: ?string}
     */
    private function matchDnsName(string $requested, string $candidate): array
    {
        $candidate = CertificateEndpoint::normalizeHostname($candidate);

        if ($candidate === '') {
            return ['matched' => false, 'identity' => null];
        }

        if ($candidate === $requested) {
            return ['matched' => true, 'identity' => $candidate];
        }

        if (!str_starts_with($candidate, '*.')) {
            return ['matched' => false, 'identity' => null];
        }

        $wildcardSuffix = substr($candidate, 2);
        if ($wildcardSuffix === '' || !str_contains($wildcardSuffix, '.')) {
            return ['matched' => false, 'identity' => null];
        }

        if ($requested === $wildcardSuffix) {
            return ['matched' => false, 'identity' => null];
        }

        $requestedLabels = explode('.', $requested);
        $suffixLabels = explode('.', $wildcardSuffix);

        if (count($requestedLabels) !== count($suffixLabels) + 1) {
            return ['matched' => false, 'identity' => null];
        }

        $requestedSuffix = implode('.', array_slice($requestedLabels, 1));
        if ($requestedSuffix !== $wildcardSuffix) {
            return ['matched' => false, 'identity' => null];
        }

        $wildcardLabel = $requestedLabels[0];
        if ($wildcardLabel === '' || str_contains($wildcardLabel, '.')) {
            return ['matched' => false, 'identity' => null];
        }

        return ['matched' => true, 'identity' => $candidate];
    }
}
