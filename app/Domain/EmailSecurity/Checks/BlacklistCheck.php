<?php

namespace App\Domain\EmailSecurity\Checks;

use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Models\Scan;
use App\Services\BlacklistChecker;

final class BlacklistCheck implements SecurityCheckInterface
{
    public function __construct(
        private BlacklistChecker $blacklistChecker,
    ) {
    }

    public function key(): string
    {
        return 'blacklist';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $scan = Scan::query()->findOrFail($context->scanId);

        return new CheckExecutionResultDTO(
            result: $this->runForScan($scan, $context->domainName),
        );
    }

    public function runForScan(Scan $scan, string $domain): CheckResultDTO
    {
        $this->blacklistChecker->checkDomain($scan, $domain);
        $summary = $this->blacklistChecker->getScanSummary($scan);

        return new CheckResultDTO(
            key: 'blacklist',
            status: !empty($summary['is_clean']) ? 'clean' : 'listed',
            data: $summary,
        );
    }
}
