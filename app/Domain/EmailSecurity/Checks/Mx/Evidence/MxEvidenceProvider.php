<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evidence;

use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxEvidenceProviderInterface;
use App\Domain\EmailSecurity\Checks\Mx\DTO\MxEvidenceDTO;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordNormalizer;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidator;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class MxEvidenceProvider implements MxEvidenceProviderInterface
{
    public function __construct(
        private MxRecordNormalizer $normalizer,
        private MtaStsPolicyValidator $policyValidator,
    ) {
    }

    public function provide(CheckContextDTO $context): MxEvidenceDTO
    {
        $native = $context->priorArtifacts[ScanArtifactKeys::NATIVE_MX_RESULT] ?? null;

        if (!$native instanceof MxNativeResult) {
            return new MxEvidenceDTO([], MxServiceMode::UNKNOWN, false, false);
        }

        $hosts = [];
        foreach ($native->targets as $target) {
            $normalized = (string) ($target['normalized_hostname'] ?? '');
            if ($normalized === '' || $normalized === '.') {
                continue;
            }

            $usable = in_array($target['status'] ?? '', [
                MxTargetResolver::STATUS_USABLE,
                MxTargetResolver::STATUS_USABLE_WITH_WARNINGS,
                MxTargetResolver::STATUS_PARTIALLY_RESOLVED,
            ], true);

            $hosts[] = [
                'hostname' => $normalized,
                'priority' => (int) ($target['preference'] ?? 0),
                'normalized_hostname' => $this->policyValidator->normalizeDomain($normalized),
                'status' => (string) ($target['status'] ?? ''),
                'usable' => $usable,
            ];
        }

        if (($native->nullMx['valid'] ?? false) === true) {
            return new MxEvidenceDTO([], MxServiceMode::NO_INBOUND_MAIL, true, false);
        }

        if ($native->serviceMode === MxServiceMode::IMPLICIT_DELIVERY) {
            $apex = $this->normalizer->normalizeDomain($native->domain);
            $addresses = array_merge(
                $native->implicitFallback['a_addresses'] ?? [],
                $native->implicitFallback['aaaa_addresses'] ?? [],
            );
            $usableAddresses = array_values(array_filter(
                $addresses,
                fn (array $item) => ($item['usable'] ?? false) === true,
            ));

            if ($usableAddresses !== []) {
                $hosts[] = [
                    'hostname' => $apex,
                    'priority' => 0,
                    'normalized_hostname' => $this->policyValidator->normalizeDomain($apex),
                    'status' => MxTargetResolver::STATUS_USABLE,
                    'usable' => true,
                ];
            }
        }

        usort($hosts, fn (array $a, array $b) => $a['priority'] <=> $b['priority']);

        return new MxEvidenceDTO(
            hosts: $hosts,
            serviceMode: $native->serviceMode,
            nullMxValid: (bool) ($native->nullMx['valid'] ?? false),
            implicitFallbackActive: (bool) ($native->implicitFallback['active'] ?? false),
        );
    }
}
