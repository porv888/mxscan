<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxAddressClassifier;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordNormalizer;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class CertificateEndpointCollector
{
    public function __construct(
        private MxRecordNormalizer $domainNormalizer,
        private MxAddressClassifier $addressClassifier,
    ) {
    }

    /**
     * @return list<CertificateEndpoint>
     */
    public function collect(CheckContextDTO $context): array
    {
        $domain = $this->domainNormalizer->normalizeDomain($context->domainName);
        if ($domain === '') {
            return [];
        }

        $endpoints = [];
        $seen = [];

        $primary = CertificateEndpoint::primaryHttps($domain);
        if ($this->isAllowedHostname($primary->hostname)) {
            $endpoints[] = $primary;
            $seen[$primary->toRegistryKey()] = true;
        }

        $mtaSts = $context->priorArtifacts[ScanArtifactKeys::NATIVE_MTA_STS_RESULT] ?? null;
        if ($mtaSts instanceof MtaStsNativeResult) {
            $policyHost = CertificateEndpoint::mtaStsHttps($domain);
            if ($this->isAllowedHostname($policyHost->hostname) && !isset($seen[$policyHost->toRegistryKey()])) {
                $endpoints[] = $policyHost;
                $seen[$policyHost->toRegistryKey()] = true;
            }

            foreach ($mtaSts->mxValidation as $row) {
                $hostname = CertificateEndpoint::normalizeHostname((string) ($row['hostname'] ?? ''));
                if ($hostname === '' || isset($seen[CertificateEndpoint::registryKey(CertificateEndpoint::KIND_SMTP_MX, $hostname, CertificateEndpoint::PORT_SMTP)])) {
                    continue;
                }

                if (!$this->isAllowedHostname($hostname)) {
                    continue;
                }

                $endpoint = CertificateEndpoint::smtpMx(
                    $hostname,
                    (int) ($row['priority'] ?? 0),
                );
                $endpoints[] = $endpoint;
                $seen[$endpoint->toRegistryKey()] = true;
            }
        }

        $mxNative = $context->priorArtifacts[ScanArtifactKeys::NATIVE_MX_RESULT] ?? null;
        if ($mxNative instanceof MxNativeResult) {
            foreach ($mxNative->targets as $target) {
                $hostname = CertificateEndpoint::normalizeHostname((string) ($target['normalized_hostname'] ?? ''));
                if ($hostname === '' || $hostname === '.') {
                    continue;
                }

                $usable = in_array($target['status'] ?? '', [
                    MxTargetResolver::STATUS_USABLE,
                    MxTargetResolver::STATUS_USABLE_WITH_WARNINGS,
                    MxTargetResolver::STATUS_PARTIALLY_RESOLVED,
                ], true);

                if (!$usable) {
                    continue;
                }

                $registryKey = CertificateEndpoint::registryKey(
                    CertificateEndpoint::KIND_SMTP_MX,
                    $hostname,
                    CertificateEndpoint::PORT_SMTP,
                );

                if (isset($seen[$registryKey])) {
                    continue;
                }

                if (!$this->isAllowedHostname($hostname)) {
                    continue;
                }

                $endpoint = CertificateEndpoint::smtpMx(
                    $hostname,
                    (int) ($target['preference'] ?? 0),
                );
                $endpoints[] = $endpoint;
                $seen[$registryKey] = true;
            }
        }

        usort($endpoints, function (CertificateEndpoint $a, CertificateEndpoint $b): int {
            $kindOrder = [
                CertificateEndpoint::KIND_PRIMARY_HTTPS => 0,
                CertificateEndpoint::KIND_MTA_STS_HTTPS => 1,
                CertificateEndpoint::KIND_SMTP_MX => 2,
            ];

            $kindCompare = ($kindOrder[$a->kind] ?? 99) <=> ($kindOrder[$b->kind] ?? 99);
            if ($kindCompare !== 0) {
                return $kindCompare;
            }

            if ($a->kind === CertificateEndpoint::KIND_SMTP_MX && $b->kind === CertificateEndpoint::KIND_SMTP_MX) {
                return ($a->mxPriority ?? 0) <=> ($b->mxPriority ?? 0);
            }

            return $a->hostname <=> $b->hostname;
        });

        $maxEndpoints = (int) config('email-security.certificates.max_endpoints_per_scan', 10);

        return array_slice($endpoints, 0, max(0, $maxEndpoints));
    }

    private function isAllowedHostname(string $hostname): bool
    {
        if ($hostname === '') {
            return false;
        }

        if (filter_var($hostname, FILTER_VALIDATE_IP) !== false) {
            return $this->addressClassifier->classify($hostname)['usable'] === true;
        }

        if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $hostname)) {
            return false;
        }

        $resolved = @gethostbynamel($hostname);
        if (!is_array($resolved) || $resolved === []) {
            return true;
        }

        foreach ($resolved as $ip) {
            if ($this->addressClassifier->classify((string) $ip)['usable'] !== true) {
                return false;
            }
        }

        return true;
    }
}
