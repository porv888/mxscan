<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Monitoring;

final class CertificateRenewalDetector
{
    public const CHANGE_RENEWED = 'renewed';
    public const CHANGE_REPLACED = 'replaced';
    public const CHANGE_UNCHANGED = 'unchanged';
    public const CHANGE_UNEXPECTEDLY_CHANGED = 'unexpectedly_changed';
    public const CHANGE_UNKNOWN = 'unknown';

    /**
     * @param array<string, mixed>|null $previousEndpoint
     * @param array<string, mixed>|null $currentEndpoint
     * @return array{change_type: string, fingerprint_changed: bool, serial_changed: bool, issuer_changed: bool, valid_to_extended: bool}
     */
    public function detect(?array $previousEndpoint, ?array $currentEndpoint): array
    {
        if (!is_array($previousEndpoint) || !is_array($currentEndpoint)) {
            return [
                'change_type' => self::CHANGE_UNKNOWN,
                'fingerprint_changed' => false,
                'serial_changed' => false,
                'issuer_changed' => false,
                'valid_to_extended' => false,
            ];
        }

        $previousFingerprint = (string) ($previousEndpoint['fingerprint_sha256'] ?? '');
        $currentFingerprint = (string) ($currentEndpoint['fingerprint_sha256'] ?? '');
        $previousSerial = (string) ($previousEndpoint['serial_fingerprint'] ?? '');
        $currentSerial = (string) ($currentEndpoint['serial_fingerprint'] ?? '');
        $previousIssuer = (string) ($previousEndpoint['issuer'] ?? '');
        $currentIssuer = (string) ($currentEndpoint['issuer'] ?? '');
        $previousValidTo = $previousEndpoint['valid_to'] ?? null;
        $currentValidTo = $currentEndpoint['valid_to'] ?? null;

        $fingerprintChanged = $previousFingerprint !== '' && $currentFingerprint !== ''
            && $previousFingerprint !== $currentFingerprint;
        $serialChanged = $previousSerial !== '' && $currentSerial !== ''
            && $previousSerial !== $currentSerial;
        $issuerChanged = $previousIssuer !== '' && $currentIssuer !== ''
            && $previousIssuer !== $currentIssuer;
        $validToExtended = is_string($previousValidTo) && is_string($currentValidTo)
            && strtotime($currentValidTo) > strtotime($previousValidTo);

        if (!$fingerprintChanged && !$serialChanged && !$issuerChanged) {
            return [
                'change_type' => self::CHANGE_UNCHANGED,
                'fingerprint_changed' => false,
                'serial_changed' => false,
                'issuer_changed' => false,
                'valid_to_extended' => false,
            ];
        }

        $changeType = match (true) {
            $validToExtended && ($fingerprintChanged || $serialChanged) => self::CHANGE_RENEWED,
            $issuerChanged && ($fingerprintChanged || $serialChanged) => self::CHANGE_REPLACED,
            $fingerprintChanged || $serialChanged => self::CHANGE_UNEXPECTEDLY_CHANGED,
            default => self::CHANGE_UNKNOWN,
        };

        return [
            'change_type' => $changeType,
            'fingerprint_changed' => $fingerprintChanged,
            'serial_changed' => $serialChanged,
            'issuer_changed' => $issuerChanged,
            'valid_to_extended' => $validToExtended,
        ];
    }

    /**
     * @param list<array<string, mixed>> $previousEndpoints
     * @param list<array<string, mixed>> $currentEndpoints
     * @return list<array{endpoint_key: string, change_type: string, previous: ?array<string, mixed>, current: ?array<string, mixed>}>
     */
    public function detectAll(array $previousEndpoints, array $currentEndpoints): array
    {
        $previousByKey = [];
        foreach ($previousEndpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            $key = (string) ($endpoint['endpoint_key'] ?? '');
            if ($key !== '') {
                $previousByKey[$key] = $endpoint;
            }
        }

        $changes = [];
        foreach ($currentEndpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            $key = (string) ($endpoint['endpoint_key'] ?? '');
            if ($key === '') {
                continue;
            }

            $previous = $previousByKey[$key] ?? null;
            $detection = $this->detect($previous, $endpoint);

            $changes[] = [
                'endpoint_key' => $key,
                'change_type' => $detection['change_type'],
                'previous' => $previous,
                'current' => $endpoint,
            ];
        }

        return $changes;
    }
}
