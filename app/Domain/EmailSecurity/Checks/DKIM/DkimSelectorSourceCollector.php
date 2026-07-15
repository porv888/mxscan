<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\DTO\CheckContextDTO;

final class DkimSelectorSourceCollector
{
    public function __construct(
        private DkimSelectorNormalizer $normalizer,
        private DkimSignatureSelectorExtractor $signatureExtractor,
        private DkimConfirmedSelectorRepository $confirmedRepository,
        private DkimProviderSelectorResolver $providerResolver,
    ) {
    }

    /**
     * @return array{candidates: list<DkimSelectorCandidate>, coverage: array<string, mixed>}
     */
    public function collect(CheckContextDTO $context): array
    {
        $domain = $context->domainName;
        $services = $context->enabledServices;
        $seen = [];
        $candidates = [];
        $sourcesUsed = [];

        $add = function (string $selector, string $source) use (&$seen, &$candidates, &$sourcesUsed, $domain): void {
            if (isset($seen[$selector])) {
                return;
            }

            $normalized = $this->normalizer->normalize($selector, $domain);
            if ($normalized === null) {
                return;
            }

            $seen[$normalized['selector']] = true;
            $sourcesUsed[] = $source;
            $candidates[] = new DkimSelectorCandidate(
                selector: $normalized['selector'],
                source: $source,
                confidence: DkimSelectorSource::confidence($source),
                hostname: $normalized['hostname'],
            );
        };

        $explicit = $services['dkim_selector'] ?? null;
        if (is_string($explicit) && $explicit !== '') {
            $add($explicit, DkimSelectorSource::EXPLICIT);
        }

        $signature = $services['dkim_signature'] ?? null;
        if (is_string($signature) && $signature !== '') {
            $extracted = $this->signatureExtractor->extract($signature);
            if ($extracted !== null) {
                $add($extracted, DkimSelectorSource::SIGNATURE);
            }
        }

        foreach ($this->confirmedRepository->selectorsForDomain($domain, $context->domainId) as $selector) {
            $add($selector, DkimSelectorSource::CONFIRMED);
        }

        $providerGuess = $services['provider_guess'] ?? null;
        if (is_string($providerGuess)) {
            foreach ($this->providerResolver->selectorsForProvider($providerGuess) as $selector) {
                $add($selector, DkimSelectorSource::PROVIDER);
            }
        }

        $catalogLimit = (int) config('dkim.catalog_limit', 25);
        $catalogCount = 0;
        foreach (config('dkim.selectors', []) as $selector) {
            if ($catalogCount >= $catalogLimit) {
                break;
            }
            if (!is_string($selector)) {
                continue;
            }
            $before = count($seen);
            $add($selector, DkimSelectorSource::CATALOG);
            if (count($seen) > $before) {
                $catalogCount++;
            }
        }

        $maxSelectors = (int) config('dkim.max_selectors_per_scan', 30);
        if (count($candidates) > $maxSelectors) {
            $candidates = array_slice($candidates, 0, $maxSelectors);
        }

        return [
            'candidates' => $candidates,
            'coverage' => $this->buildCoverage($candidates, $sourcesUsed),
        ];
    }

    /**
     * @param list<DkimSelectorCandidate> $candidates
     * @param list<string> $sourcesUsed
     * @return array<string, mixed>
     */
    private function buildCoverage(array $candidates, array $sourcesUsed): array
    {
        $sourcesUsed = array_values(array_unique($sourcesUsed));

        if ($candidates === []) {
            return [
                'selectors_available' => false,
                'selectors_tested' => 0,
                'coverage_type' => 'none',
            ];
        }

        $hasAuthoritative = false;
        $hasCatalogOnly = true;

        foreach ($candidates as $candidate) {
            if (DkimSelectorSource::isAuthoritative($candidate->source)) {
                $hasAuthoritative = true;
                $hasCatalogOnly = false;
            } elseif ($candidate->source !== DkimSelectorSource::CATALOG) {
                $hasCatalogOnly = false;
            }
        }

        $coverageType = match (true) {
            !$hasAuthoritative && $hasCatalogOnly => 'catalog_only',
            in_array(DkimSelectorSource::EXPLICIT, $sourcesUsed, true)
                && in_array(DkimSelectorSource::PROVIDER, $sourcesUsed, true) => 'explicit_and_provider',
            in_array(DkimSelectorSource::EXPLICIT, $sourcesUsed, true) => 'explicit',
            in_array(DkimSelectorSource::SIGNATURE, $sourcesUsed, true) => 'signature',
            in_array(DkimSelectorSource::CONFIRMED, $sourcesUsed, true) => 'confirmed',
            in_array(DkimSelectorSource::PROVIDER, $sourcesUsed, true) => 'provider',
            default => 'catalog_only',
        };

        return [
            'selectors_available' => true,
            'selectors_tested' => count($candidates),
            'coverage_type' => $coverageType,
        ];
    }
}
