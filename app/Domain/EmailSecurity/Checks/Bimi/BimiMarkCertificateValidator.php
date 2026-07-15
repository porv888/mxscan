<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiClockInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiTrustStoreInterface;

final class BimiMarkCertificateValidator
{
    public function __construct(
        private BimiMarkCertificateParser $certificateParser,
        private BimiTrustStoreInterface $trustStore,
        private BimiClockInterface $clock,
    ) {
    }

    /**
     * @param list<array<string, mixed>> $certificates
     * @return array<string, mixed>
     */
    public function validate(array $certificates, string $assertedDomain): array
    {
        if ($certificates === []) {
            return [
                'status' => 'malformed',
                'type' => null,
                'trusted' => false,
                'partially_evaluated' => false,
                'domain_match' => 'mismatch',
                'errors' => [[
                    'code' => 'NO_CERTIFICATES',
                    'message' => 'No certificates available for validation.',
                ]],
                'warnings' => [],
                'valid_to' => null,
                'days_until_expiry' => null,
            ];
        }

        $leaf = $certificates[0];
        $type = $this->certificateParser->classifyType($leaf);
        $errors = [];
        $warnings = [];

        if ($type === 'unknown') {
            return [
                'status' => 'unsupported',
                'type' => $type,
                'trusted' => false,
                'partially_evaluated' => false,
                'domain_match' => $this->domainMatch($leaf, $assertedDomain),
                'errors' => [[
                    'code' => 'UNSUPPORTED_EVIDENCE',
                    'message' => 'Certificate is not a recognized Mark Certificate profile.',
                ]],
                'warnings' => [],
                'valid_to' => $leaf['valid_to'] ?? null,
                'days_until_expiry' => $this->daysUntilExpiry($leaf['valid_to'] ?? null),
            ];
        }

        $pemChain = array_map(fn (array $cert) => (string) ($cert['pem'] ?? ''), $certificates);
        $trust = $this->trustStore->verifyChain($pemChain);
        $partiallyEvaluated = false;

        if (!$trust['trusted']) {
            if ($trust['warnings'] !== []) {
                $partiallyEvaluated = true;
                foreach ($trust['warnings'] as $warning) {
                    $warnings[] = [
                        'code' => 'TRUST_VALIDATION_PARTIAL',
                        'message' => $warning,
                    ];
                }
            } else {
                foreach ($trust['errors'] as $error) {
                    $errors[] = [
                        'code' => 'TRUST_VALIDATION_FAILED',
                        'message' => $error,
                    ];
                }
            }
        }

        $validTo = $leaf['valid_to'] ?? null;
        $daysUntilExpiry = $this->daysUntilExpiry($validTo);
        $expiryWarningDays = (int) config('bimi.mark_certificate.expiry_warning_days', 30);

        if (is_int($daysUntilExpiry) && $daysUntilExpiry < 0) {
            $errors[] = [
                'code' => 'CERTIFICATE_EXPIRED',
                'message' => 'Mark Certificate has expired.',
            ];
        } elseif (is_int($daysUntilExpiry) && $daysUntilExpiry <= $expiryWarningDays) {
            $warnings[] = [
                'code' => 'CERTIFICATE_EXPIRING',
                'message' => 'Mark Certificate is expiring soon.',
            ];
        }

        $domainMatch = $this->domainMatch($leaf, $assertedDomain);
        if ($domainMatch === 'mismatch') {
            $errors[] = [
                'code' => 'DOMAIN_MISMATCH',
                'message' => 'Mark Certificate domain does not match asserted domain.',
            ];
        }

        $status = match (true) {
            $errors !== [] => 'invalid',
            $partiallyEvaluated => 'partially_validated',
            default => 'valid',
        };

        return [
            'status' => $status,
            'type' => $type,
            'trusted' => $trust['trusted'],
            'partially_evaluated' => $partiallyEvaluated,
            'domain_match' => $domainMatch,
            'errors' => $errors,
            'warnings' => $warnings,
            'valid_to' => $validTo,
            'days_until_expiry' => $daysUntilExpiry,
            'fingerprint_sha256' => $leaf['fingerprint_sha256'] ?? null,
        ];
    }

    /**
     * @param array<string, mixed> $certificate
     */
    private function domainMatch(array $certificate, string $assertedDomain): string
    {
        $assertedDomain = strtolower(rtrim(trim($assertedDomain), '.'));
        $extensions = $certificate['extensions'] ?? [];
        if (!is_array($extensions)) {
            return 'mismatch';
        }

        $san = strtolower((string) ($extensions['subjectAltName'] ?? ''));
        $cn = '';
        $subject = $certificate['subject'] ?? [];
        if (is_array($subject) && isset($subject['CN'])) {
            $cn = strtolower((string) $subject['CN']);
        }

        $candidates = array_filter([$cn, $san]);
        foreach ($candidates as $candidate) {
            if ($candidate === $assertedDomain) {
                return 'exact';
            }
            if (str_contains($candidate, $assertedDomain)) {
                return 'organizational';
            }
        }

        return 'mismatch';
    }

    private function daysUntilExpiry(?string $validTo): ?int
    {
        if (!is_string($validTo) || $validTo === '') {
            return null;
        }

        $expiry = strtotime($validTo);
        if ($expiry === false) {
            return null;
        }

        $now = $this->clock->now()->getTimestamp();

        return (int) floor(($expiry - $now) / 86400);
    }
}
