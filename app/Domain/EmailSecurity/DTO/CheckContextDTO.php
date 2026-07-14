<?php

namespace App\Domain\EmailSecurity\DTO;

use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Support\Carbon;

final class CheckContextDTO
{
    /**
     * @param array{dns: bool, spf: bool, blacklist: bool, monitoring?: bool} $enabledServices
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
    ) {
    }

    public static function fromExecution(Domain $domain, Scan $scan, ScanOptionsDTO $options): self
    {
        $scanType = ScanPayloadBuilder::determineScanType([
            'dns' => $options->dns,
            'spf' => $options->spf,
            'blacklist' => $options->blacklist,
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
                'monitoring' => $options->monitoring,
            ],
            environment: app()->environment(),
            correlationId: (string) $scan->id,
            executedAt: Carbon::now()->toIso8601String(),
        );
    }
}
