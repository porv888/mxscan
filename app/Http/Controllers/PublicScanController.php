<?php

namespace App\Http\Controllers;

use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class PublicScanController extends Controller
{
    public function __construct(
        private EmailSecurityScanService $scanService,
    ) {
    }

    /**
     * Landing page with scan input.
     */
    public function index()
    {
        if (auth()->check()) {
            return redirect()->route('dashboard');
        }

        return view('public.scan');
    }

    /**
     * Run a lightweight public scan via the native email security pipeline.
     */
    public function scan(Request $request)
    {
        $request->validate([
            'domain' => 'required|string|max:253|regex:/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/',
            'dkim_selector' => 'nullable|string|max:253',
            'dkim_signature' => 'nullable|string|max:4096',
        ]);

        $domainName = strtolower(trim($request->input('domain')));

        try {
            $domain = new Domain(['domain' => $domainName]);
            $scan = new Scan(['status' => 'running']);
            $options = ScanOptionsDTO::fromArray([
                'dns' => true,
                'spf' => true,
                'blacklist' => false,
                'dkim_selector' => $request->input('dkim_selector'),
                'dkim_signature' => $request->input('dkim_signature'),
            ]);

            $execution = $this->scanService->execute(
                $domain,
                $scan,
                $options,
                microtime(true),
            );

            $results = $execution->resultJson;
            $results['score'] = $execution->score ?? ($results['dns']['score'] ?? 0);
            $results['records'] = $results['dns']['records'] ?? [];
            $results['recommendations'] = array_map(
                static fn (array $item): array => [
                    'type' => $item['severity'] ?? 'info',
                    'title' => $item['title'] ?? '',
                    'description' => $item['explanation'] ?? '',
                ],
                $execution->recommendations,
            );
            $domain = $domainName;
        } catch (\Exception $e) {
            Log::warning("Public scan failed for {$domainName}: " . $e->getMessage());

            return back()->withInput()->withErrors(['domain' => 'Unable to scan this domain. Please check the domain name and try again.']);
        }

        return view('public.scan-result', compact('domain', 'results'));
    }
}
