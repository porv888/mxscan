<?php

namespace App\Http\Controllers;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiIndicatorPreviewStore;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiLogoRasterizer;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

final class BimiLogoPreviewController extends Controller
{
    public function __construct(
        private BimiIndicatorPreviewStore $previewStore,
        private BimiLogoRasterizer $rasterizer,
    ) {
        $this->middleware(['auth', 'verified']);
    }

    public function show(Domain $domain, Scan $scan): Response
    {
        if ($domain->user_id !== Auth::id() || $scan->user_id !== Auth::id() || $scan->domain_id !== $domain->id) {
            abort(403, 'Unauthorized access to BIMI preview.');
        }

        $resultJson = is_array($scan->result_json) ? $scan->result_json : [];
        $analysis = BimiAnalysisReader::analysis($resultJson['bimi'] ?? null);
        if ($analysis === null || ($analysis['indicator']['status'] ?? '') !== 'valid') {
            abort(404);
        }

        $sha256 = (string) ($analysis['indicator']['sha256'] ?? '');
        $previewRef = $analysis['indicator']['preview_ref'] ?? null;
        if ($sha256 === ''
            || !is_array($previewRef)
            || (string) ($previewRef['scan_id'] ?? '') !== (string) $scan->id
            || (string) ($previewRef['sha256'] ?? '') !== $sha256) {
            abort(404);
        }

        $svg = $this->previewStore->retrieve((string) $scan->id, $sha256);
        if ($svg === null) {
            abort(404);
        }

        $cacheTtl = (int) config('bimi.preview.cache_ttl_seconds', 3600);
        $png = $this->rasterizer->rasterize($svg);
        if ($png !== null) {
            return response($png, 200, [
                'Content-Type' => 'image/png',
                'X-Content-Type-Options' => 'nosniff',
                'Cache-Control' => 'private, max-age=' . $cacheTtl,
                'Content-Disposition' => 'inline; filename="bimi-logo.png"',
            ]);
        }

        return response($svg, 200, [
            'Content-Type' => 'image/svg+xml',
            'X-Content-Type-Options' => 'nosniff',
            'Cache-Control' => 'private, max-age=' . $cacheTtl,
            'Content-Security-Policy' => "default-src 'none'; style-src 'none'; script-src 'none'",
            'Content-Disposition' => 'inline; filename="bimi-logo.svg"',
        ]);
    }
}
