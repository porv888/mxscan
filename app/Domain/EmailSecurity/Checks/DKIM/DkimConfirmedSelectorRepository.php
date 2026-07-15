<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

use App\Models\DmarcSender;
use App\Models\Scan;

final class DkimConfirmedSelectorRepository
{
    /**
     * @return list<string>
     */
    public function selectorsForDomain(string $domain, ?int $domainId = null): array
    {
        $selectors = [];

        if ($domainId !== null) {
            $selectors = array_merge($selectors, $this->fromPriorScans($domainId));
            $selectors = array_merge($selectors, $this->fromDmarcSenders($domainId));
        }

        return array_values(array_unique(array_filter($selectors)));
    }

    /**
     * @return list<string>
     */
    private function fromPriorScans(int $domainId): array
    {
        $selectors = [];

        $scans = Scan::query()
            ->where('domain_id', $domainId)
            ->whereNotNull('result_json')
            ->orderByDesc('id')
            ->limit(5)
            ->get(['result_json']);

        foreach ($scans as $scan) {
            $analysis = $scan->result_json['dkim']['analysis'] ?? null;
            if (!is_array($analysis)) {
                continue;
            }

            foreach ($analysis['selectors'] ?? [] as $row) {
                if (!is_array($row)) {
                    continue;
                }
                if (($row['record_status'] ?? '') === 'valid' && is_string($row['selector'] ?? null)) {
                    $selectors[] = $row['selector'];
                }
            }
        }

        return $selectors;
    }

    /**
     * @return list<string>
     */
    private function fromDmarcSenders(int $domainId): array
    {
        return DmarcSender::query()
            ->where('domain_id', $domainId)
            ->whereNotNull('dkim_selector')
            ->where('dkim_selector', '!=', '')
            ->pluck('dkim_selector')
            ->unique()
            ->values()
            ->all();
    }
}
