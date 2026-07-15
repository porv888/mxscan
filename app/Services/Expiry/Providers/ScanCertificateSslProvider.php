<?php

namespace App\Services\Expiry\Providers;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Services\Expiry\Contracts\SslExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;

class ScanCertificateSslProvider implements SslExpiryProvider
{
    /**
     * @param array<string, mixed>|null $certificatesSection
     */
    public function detectFromScanSection(?array $certificatesSection): ExpiryResult
    {
        $start = microtime(true);
        $analysis = CertificateAnalysisReader::analysis($certificatesSection);

        if ($analysis === null) {
            return ExpiryResult::failure(
                $this->getName(),
                'No native certificate analysis available',
                (microtime(true) - $start) * 1000,
            );
        }

        $earliest = is_array($analysis['earliest_expiry'] ?? null) ? $analysis['earliest_expiry'] : null;
        $expiresAt = is_string($earliest['expires_at'] ?? null) ? $earliest['expires_at'] : null;

        if ($expiresAt === null) {
            foreach ($analysis['endpoints'] ?? [] as $endpoint) {
                if (!is_array($endpoint)) {
                    continue;
                }
                if (($endpoint['endpoint_type'] ?? '') !== CertificateEndpoint::KIND_PRIMARY_HTTPS) {
                    continue;
                }
                $expiresAt = is_string($endpoint['valid_to'] ?? null) ? $endpoint['valid_to'] : null;
                break;
            }
        }

        if ($expiresAt === null) {
            return ExpiryResult::failure(
                $this->getName(),
                'No primary HTTPS certificate expiry in scan analysis',
                (microtime(true) - $start) * 1000,
            );
        }

        return ExpiryResult::success(
            Carbon::parse($expiresAt),
            $this->getName(),
            (microtime(true) - $start) * 1000,
        );
    }

    public function detect(string $domain): ExpiryResult
    {
        return ExpiryResult::failure(
            $this->getName(),
            'Scan certificate provider requires scan analysis payload',
            0,
        );
    }

    public function getName(): string
    {
        return 'Scan Certificate Analysis';
    }

    public function isEnabled(): bool
    {
        return true;
    }
}
