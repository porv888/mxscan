<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Support;

use Illuminate\Support\Facades\Storage;

final class BimiIndicatorPreviewStore
{
    public function store(?string $scanId, string $sha256, string $svgBytes): bool
    {
        if ($scanId === null || $scanId === '') {
            return false;
        }

        $maxBytes = (int) config('bimi.svg_max_bytes', 32768);
        if (strlen($svgBytes) > $maxBytes) {
            return false;
        }

        if (hash('sha256', $svgBytes) !== $sha256) {
            return false;
        }

        return Storage::disk($this->disk())->put($this->path($scanId, $sha256), $svgBytes);
    }

    public function retrieve(string $scanId, string $expectedSha256): ?string
    {
        if (!$this->exists($scanId, $expectedSha256)) {
            return null;
        }

        $bytes = Storage::disk($this->disk())->get($this->path($scanId, $expectedSha256));

        return is_string($bytes) ? $bytes : null;
    }

    public function exists(string $scanId, string $sha256): bool
    {
        if ($scanId === '' || $sha256 === '') {
            return false;
        }

        if (!Storage::disk($this->disk())->exists($this->path($scanId, $sha256))) {
            return false;
        }

        $bytes = Storage::disk($this->disk())->get($this->path($scanId, $sha256));
        if (!is_string($bytes)) {
            return false;
        }

        return hash('sha256', $bytes) === $sha256;
    }

    private function disk(): string
    {
        return (string) config('bimi.preview.disk', 'local');
    }

    private function path(string $scanId, string $sha256): string
    {
        $prefix = trim((string) config('bimi.preview.path_prefix', 'private/bimi-indicators'), '/');

        return $prefix . '/' . $scanId . '/' . $sha256 . '.svg';
    }
}
