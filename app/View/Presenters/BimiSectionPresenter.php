<?php

namespace App\View\Presenters;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiIndicatorPreviewStore;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiPublicPrivacyFilter;
use App\Models\Domain;
use App\Models\Scan;

final class BimiSectionPresenter
{
    public function __construct(
        protected ?array $bimiInfo = null,
        protected ?array $legacyDnsRecord = null,
        protected ?Domain $domain = null,
        protected ?Scan $scan = null,
        protected ?BimiPublicPrivacyFilter $privacyFilter = null,
        protected ?BimiIndicatorPreviewStore $previewStore = null,
    ) {
    }

    /**
     * @return array<string, mixed>|null
     */
    public function publicSummary(): ?array
    {
        $filter = $this->privacyFilter ?? app(BimiPublicPrivacyFilter::class);

        return $filter->filterFromResult($this->bimiInfo, $this->legacyDnsRecord);
    }

    public function previewUrl(): ?string
    {
        if ($this->domain === null || $this->scan === null) {
            return null;
        }

        $analysis = BimiAnalysisReader::analysis($this->bimiInfo);
        if ($analysis === null || ($analysis['indicator']['status'] ?? '') !== 'valid') {
            return null;
        }

        $sha256 = (string) ($analysis['indicator']['sha256'] ?? '');
        $previewRef = $analysis['indicator']['preview_ref'] ?? null;
        if ($sha256 === ''
            || !is_array($previewRef)
            || (string) ($previewRef['scan_id'] ?? '') !== (string) $this->scan->id) {
            return null;
        }

        $store = $this->previewStore ?? app(BimiIndicatorPreviewStore::class);
        if (!$store->exists((string) $this->scan->id, $sha256)) {
            return null;
        }

        return route('domains.bimi.preview', [$this->domain, $this->scan]);
    }

    public function logoValidationLabel(?string $status = null): string
    {
        $status ??= (string) ($this->publicSummary()['logo_validation_status'] ?? 'absent');

        return match ($status) {
            'valid' => 'Valid SVG',
            'invalid' => 'Invalid SVG',
            'unavailable' => 'Unavailable',
            'not_checked' => 'Not checked',
            default => 'Not configured',
        };
    }
}
