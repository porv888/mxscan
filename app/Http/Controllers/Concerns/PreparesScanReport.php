<?php

namespace App\Http\Controllers\Concerns;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Models\Scan;

trait PreparesScanReport
{
    /**
     * @return array<string, mixed>
     */
    protected function prepareScanReportViewData(Scan $scan): array
    {
        $scan->loadMissing(['domain', 'blacklistResults']);

        return app(ScanReportFactoryInterface::class)->build($scan, $scan->domain)->toArray();
    }
}
