<?php

namespace App\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Compatibility\DmarcLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcOrganizationalDomainResolver;
use App\Domain\EmailSecurity\Checks\DMARC\Evidence\DmarcEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\DMARC\Validation\DmarcValidator;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class DmarcCheck implements SecurityCheckInterface
{
    public function __construct(
        private DmarcOrganizationalDomainResolver $orgResolver,
        private DmarcValidator $validator,
        private DmarcEvidenceBuilder $evidenceBuilder,
        private DmarcLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'dmarc';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $domain = $context->domainName;
        $discoveryMeta = $this->orgResolver->resolve($domain, $dns);
        $expectedRua = $context->enabledServices['dmarc_expected_rua'] ?? null;
        $expectedRua = is_string($expectedRua) ? $expectedRua : null;

        if (($discoveryMeta['exact_discovery'] ?? null)?->hasDnsFailure()
            && ($discoveryMeta['policy_discovery'] ?? null) === null
            && ($discoveryMeta['partially_evaluated'] ?? false)) {
            $native = $this->evidenceBuilder->build($discoveryMeta, null, $expectedRua);
        } elseif (($discoveryMeta['policy_discovery'] ?? null) === null
            && ($discoveryMeta['policy_source'] ?? 'none') === 'none') {
            $native = $this->evidenceBuilder->build($discoveryMeta, null, $expectedRua);
        } else {
            $policyDiscovery = $discoveryMeta['policy_discovery'];
            $validation = $this->validator->validate($policyDiscovery, $policyDiscovery->record);
            $native = $this->evidenceBuilder->build($discoveryMeta, $validation, $expectedRua);
        }

        $legacyPayload = $this->legacyAdapter->toResultJsonDmarc($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'dmarc',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_DMARC_RESULT => $native,
                ScanArtifactKeys::DMARC_DNS_COMPAT => $this->legacyAdapter->toDnsRecordCompat($native),
            ],
        );
    }
}
