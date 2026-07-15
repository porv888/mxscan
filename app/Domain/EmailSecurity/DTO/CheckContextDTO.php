<?php

namespace App\Domain\EmailSecurity\DTO;

use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Support\Carbon;

final class CheckContextDTO
{
    /**
     * @param array{dns: bool, spf: bool, blacklist: bool, dkim?: bool, monitoring?: bool, dkim_selector?: ?string, dkim_signature?: ?string, provider_guess?: ?string, dmarc_expected_rua?: ?string} $enabledServices
     * @param array<string, mixed> $priorArtifacts
     */
    public function __construct(
        public readonly string $domainName,
        public readonly ?int $domainId,
        public readonly ?string $scanId,
        public readonly string $scanType,
        public readonly array $enabledServices,
        public readonly string $environment,
        public readonly string $correlationId,
        public readonly string $executedAt,
        public readonly array $priorArtifacts = [],
    ) {
    }

    /**
     * @param array<string, mixed> $priorArtifacts
     */
    public function withPriorArtifacts(array $priorArtifacts): self
    {
        return new self(
            domainName: $this->domainName,
            domainId: $this->domainId,
            scanId: $this->scanId,
            scanType: $this->scanType,
            enabledServices: $this->enabledServices,
            environment: $this->environment,
            correlationId: $this->correlationId,
            executedAt: $this->executedAt,
            priorArtifacts: $priorArtifacts,
        );
    }

    public static function fromExecution(Domain $domain, Scan $scan, ScanOptionsDTO $options): self
    {
        $scanType = ScanPayloadBuilder::determineScanType([
            'dns' => $options->dns,
            'spf' => $options->spf,
            'blacklist' => $options->blacklist,
            'dkim' => $options->dkim,
        ]);

        return new self(
            domainName: $domain->domain,
            domainId: $domain->id,
            scanId: $scan->id,
            scanType: $scanType,
            enabledServices: [
                'dns' => $options->dns,
                'spf' => $options->spf,
                'blacklist' => $options->blacklist,
                'dkim' => $options->dkim,
                'monitoring' => $options->monitoring,
                'dkim_selector' => $options->dkimSelector,
                'dkim_signature' => $options->dkimSignature,
                'provider_guess' => $domain->provider_guess,
                'dmarc_expected_rua' => $domain->dmarc_rua_email,
            ],
            environment: app()->environment(),
            correlationId: (string) $scan->id,
            executedAt: Carbon::now()->toIso8601String(),
        );
    }
}
