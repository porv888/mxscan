<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateProbeInterface;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateNormalizedEvidence;

final class CertificateProbeCoordinator
{
    /** @var array<string, CertificateNormalizedEvidence> */
    private array $registry = [];

    public function register(string $key, CertificateNormalizedEvidence $evidence): void
    {
        $this->registry[$key] = $evidence;
    }

    public function get(string $key): ?CertificateNormalizedEvidence
    {
        return $this->registry[$key] ?? null;
    }

    public function has(string $key): bool
    {
        return isset($this->registry[$key]);
    }

    public function probeIfAbsent(CertificateEndpoint $endpoint, CertificateProbeInterface $probe): CertificateNormalizedEvidence
    {
        $key = $endpoint->toRegistryKey();
        $existing = $this->get($key);
        if ($existing instanceof CertificateNormalizedEvidence) {
            return $existing;
        }

        $evidence = $probe->probe($endpoint);
        $this->register($key, $evidence);

        return $evidence;
    }

    /**
     * @return list<CertificateNormalizedEvidence>
     */
    public function all(): array
    {
        return array_values($this->registry);
    }
}
