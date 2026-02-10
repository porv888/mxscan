<?php

namespace App\Http\Controllers;

use App\Services\ScannerService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class PublicScanController extends Controller
{
    /**
     * Landing page with scan input.
     */
    public function index()
    {
        // If user is authenticated, redirect to dashboard
        if (auth()->check()) {
            return redirect()->route('dashboard');
        }

        return view('public.scan');
    }

    /**
     * Run a lightweight public scan.
     */
    public function scan(Request $request, ScannerService $scanner)
    {
        $request->validate([
            'domain' => 'required|string|max:253|regex:/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/',
        ]);

        $domain = strtolower(trim($request->input('domain')));

        try {
            $results = $scanner->scanDomain($domain);
        } catch (\Exception $e) {
            Log::warning("Public scan failed for {$domain}: " . $e->getMessage());
            return back()->withInput()->withErrors(['domain' => 'Unable to scan this domain. Please check the domain name and try again.']);
        }

        return view('public.scan-result', compact('domain', 'results'));
    }
}
