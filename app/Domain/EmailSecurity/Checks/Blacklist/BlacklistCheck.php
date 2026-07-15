<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Models\Scan;

final class BlacklistCheck implements SecurityCheckInterface
{
    public function __construct(
        private BlacklistScanOrchestrator $orchestrator,
    ) {
    }

    public function key(): string
    {
        return 'blacklist';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $scan = Scan::query()->findOrFail($context->scanId);
        $execution = $this->orchestrator->run($scan, $context);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'blacklist',
                status: $execution['native']->state,
                data: $execution['payload'],
                messages: [$execution['native']->summary],
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_BLACKLIST_RESULT => $execution['native'],
            ],
        );
    }
}
