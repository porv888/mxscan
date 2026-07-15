<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\Discovery\DkimRecordDiscovery;
use App\Domain\EmailSecurity\Checks\DKIM\Evidence\DkimEvidenceBuilder;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;

final class DkimAnalysisService
{
    public function __construct(
        private DkimSelectorSourceCollector $sourceCollector,
        private DkimRecordDiscovery $recordDiscovery,
        private DkimEvidenceBuilder $evidenceBuilder,
    ) {
    }

    public function analyze(CheckContextDTO $context): DkimNativeResult
    {
        $collected = $this->sourceCollector->collect($context);
        $discoveries = [];

        foreach ($collected['candidates'] as $candidate) {
            $discoveries[] = $this->recordDiscovery->discover($candidate);
        }

        return $this->evidenceBuilder->build(
            $context->domainName,
            $discoveries,
            $collected['coverage'],
        );
    }
}
