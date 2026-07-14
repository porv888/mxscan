<?php

namespace App\Domain\EmailSecurity\Checks;

use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Services\Spf\SpfResolver;

final class SpfAnalysisCheck implements SecurityCheckInterface
{
    public function __construct(
        private SpfResolver $spfResolver,
    ) {
    }

    public function key(): string
    {
        return 'spf';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $result = $this->spfResolver->resolve($context->domainName);
        $payload = ScanPayloadBuilder::buildSpfResultPayload($result);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'spf',
                status: $payload['status'] ?? 'safe',
                data: $payload,
                messages: $payload['warnings'] ?? [],
            ),
            artifacts: [
                ScanArtifactKeys::LEGACY_SPF_RAW => $result,
            ],
        );
    }
}
