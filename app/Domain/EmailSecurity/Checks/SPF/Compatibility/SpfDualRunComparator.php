<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Compatibility;

use App\Domain\EmailSecurity\Checks\SPF\SpfCheck;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;

/**
 * Test-only utility to compare legacy and native SPF outputs.
 */
final class SpfDualRunComparator
{
    public function __construct(
        private SpfResolver $legacyResolver,
        private SpfCheck $nativeCheck,
    ) {
    }

    /**
     * @return array{legacy: SpfResultDTO, native: SpfResultDTO, equal: bool, diffs: list<string>}
     */
    public function compare(string $domain, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns = null): array
    {
        $legacy = $this->legacyResolver->resolve($domain);

        $context = CheckContextDTO::fromExecution(
            new Domain(['domain' => $domain]),
            new Scan(['id' => '00000000-0000-4000-8000-000000000010']),
            ScanOptionsDTO::fromArray(['dns' => $dns !== null, 'spf' => true, 'blacklist' => false]),
        );
        $nativeExecution = $this->nativeCheck->run($context, $dns);
        $native = $nativeExecution->artifacts['legacy_spf_raw'];

        $diffs = [];
        if ($legacy->currentRecord !== $native->currentRecord) {
            $diffs[] = 'currentRecord';
        }
        if ($legacy->lookupsUsed !== $native->lookupsUsed) {
            $diffs[] = 'lookupsUsed';
        }
        if ($legacy->flattenedSpf !== $native->flattenedSpf) {
            $diffs[] = 'flattenedSpf';
        }
        if ($legacy->warnings !== $native->warnings) {
            $diffs[] = 'warnings';
        }

        return [
            'legacy' => $legacy,
            'native' => $native,
            'equal' => $diffs === [],
            'diffs' => $diffs,
        ];
    }
}
