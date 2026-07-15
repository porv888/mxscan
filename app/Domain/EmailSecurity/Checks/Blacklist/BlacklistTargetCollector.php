<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxAddressClassifier;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\Compatibility\MxNativeAnalysisPayload;

final class BlacklistTargetCollector
{
    public function __construct(
        private MxAddressClassifier $addressClassifier,
    ) {
    }

    /**
     * @return array{reason: ?string, targets: list<BlacklistTarget>, null_mx: bool, mx_evidence_version: ?string}
     */
    public function collect(?MxNativeResult $mxNative): array
    {
        if (!$mxNative instanceof MxNativeResult) {
            return [
                'reason' => 'Native MX evidence unavailable.',
                'targets' => [],
                'null_mx' => false,
                'mx_evidence_version' => null,
            ];
        }

        if (($mxNative->nullMx['valid'] ?? false) === true) {
            return [
                'reason' => 'no inbound mail targets',
                'targets' => [],
                'null_mx' => true,
                'mx_evidence_version' => MxNativeAnalysisPayload::VERSION,
            ];
        }

        /** @var array<string, BlacklistTarget> $deduped */
        $deduped = [];

        foreach ($mxNative->targets as $target) {
            $status = (string) ($target['status'] ?? '');
            if (!in_array($status, [
                MxTargetResolver::STATUS_USABLE,
                MxTargetResolver::STATUS_USABLE_WITH_WARNINGS,
                MxTargetResolver::STATUS_PARTIALLY_RESOLVED,
            ], true)) {
                continue;
            }

            $hostname = (string) ($target['normalized_hostname'] ?? $target['hostname'] ?? '');
            foreach (array_merge($target['a_addresses'] ?? [], $target['aaaa_addresses'] ?? []) as $addressRow) {
                $this->addAddress($deduped, (string) ($addressRow['address'] ?? ''), 'mx_target', $hostname);
            }
        }

        if ($mxNative->serviceMode === MxServiceMode::IMPLICIT_DELIVERY) {
            $apex = strtolower(rtrim($mxNative->domain, '.'));
            foreach ($mxNative->implicitFallback['a_addresses'] ?? [] as $addressRow) {
                if (($addressRow['usable'] ?? false) === true) {
                    $this->addAddress($deduped, (string) ($addressRow['address'] ?? ''), 'implicit_mx', $apex);
                }
            }
            foreach ($mxNative->implicitFallback['aaaa_addresses'] ?? [] as $addressRow) {
                if (($addressRow['usable'] ?? false) === true) {
                    $this->addAddress($deduped, (string) ($addressRow['address'] ?? ''), 'implicit_mx', $apex);
                }
            }
        }

        return [
            'reason' => $deduped === [] ? 'No applicable public MX targets.' : null,
            'targets' => array_values($deduped),
            'null_mx' => false,
            'mx_evidence_version' => MxNativeAnalysisPayload::VERSION,
        ];
    }

    /**
     * @param array<string, BlacklistTarget> $deduped
     */
    private function addAddress(array &$deduped, string $address, string $sourceType, string $hostname): void
    {
        $classified = $this->addressClassifier->classify($address);
        if (($classified['usable'] ?? false) !== true) {
            return;
        }

        $version = str_contains($address, ':') ? 6 : 4;
        $key = $version . ':' . strtolower($address);

        if (!isset($deduped[$key])) {
            $deduped[$key] = new BlacklistTarget(
                address: $address,
                version: $version,
                sourceType: $sourceType,
                sourceHostnames: $hostname !== '' ? [$hostname] : [],
            );

            return;
        }

        $existing = $deduped[$key];
        $hostnames = $existing->sourceHostnames;
        if ($hostname !== '' && !in_array($hostname, $hostnames, true)) {
            $hostnames[] = $hostname;
        }

        $deduped[$key] = new BlacklistTarget(
            address: $existing->address,
            version: $existing->version,
            sourceType: $existing->sourceType,
            sourceHostnames: $hostnames,
        );
    }
}
