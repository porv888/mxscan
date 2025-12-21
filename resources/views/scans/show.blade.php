@extends('layouts.app')

@section('content')
<div class="p-6 space-y-6">

    {{-- Header --}}
    <div class="flex items-start justify-between">
        <div>
            <h1 class="text-2xl font-semibold text-gray-900 dark:text-gray-100">{{ $domain->domain }}</h1>
            <div class="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Scanned at {{ $scan->finished_at?->timezone(auth()->user()->timezone ?? 'UTC')->format('M d, Y H:i') ?? $scan->created_at->format('M d, Y H:i') }}
                • Scan Type: {{ $scan->getTypeLabel() }}
                • ID: {{ Str::limit($scan->id, 8, '') }}
            </div>
        </div>
        <div class="flex gap-2">
            <form method="POST" action="{{ route('domains.scan.now', $domain) }}">
                @csrf
                <input type="hidden" name="mode" value="full">
                <button class="inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-600 transition-colors">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                    </svg>
                    Re-scan
                </button>
            </form>
            <button onclick="downloadReport()" class="inline-flex items-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 dark:bg-gray-800 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-700 transition-colors">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                Download
            </button>
            <button onclick="shareReport()" class="inline-flex items-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 dark:bg-gray-800 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-700 transition-colors">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.367 2.684 3 3 0 00-5.367-2.684z"></path>
                </svg>
                Share
            </button>
        </div>
    </div>

    {{-- KPI Cards --}}
    @include('scans.partials._kpi-cards', [
        'enabled' => $enabled,
        'score' => $scan->score,
        'scoreDelta' => $scoreDelta,
        'blacklistHits' => $blacklistHits,
        'blacklistTotal' => $blacklistTotal,
        'spfLookupCount' => $spfLookupCount,
        'spfMax' => $spfMax,
        'dmarcPolicy' => $dmarcPolicy,
        'dmarcAligned' => $dmarcAligned,
        'tlsrptOk' => $tlsrptOk,
        'mtastsOk' => $mtastsOk,
        'domainDays' => $domainDays,
        'sslDays' => $sslDays,
    ])

    {{-- Incidents Strip --}}
    @include('scans.partials._incidents-strip', ['incidents' => $incidents])

    {{-- Two-Column Layout: Service Sections + Fix Pack --}}
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {{-- Left Column: Service Sections --}}
        <div class="lg:col-span-2 space-y-6">
            
            {{-- DNS Security Section --}}
            @if($enabled['dns'])
                @include('scans.partials._dns-section', [
                    'records' => $records,
                    'spfLookupCount' => $spfLookupCount,
                    'domain' => $domain,
                ])
            @endif

            {{-- Blacklist Section --}}
            @if($enabled['blacklist'])
                @include('scans.partials._blacklist-section', [
                    'blacklistHits' => $blacklistHits,
                    'blacklistTotal' => $blacklistTotal,
                    'rows' => $blacklistRows,
                    'domain' => $domain,
                ])
            @endif

            {{-- Delivery Section --}}
            @if($enabled['delivery'] && $deliveries->count() > 0)
                @include('scans.partials._delivery-section', [
                    'deliveries' => $deliveries,
                    'domain' => $domain,
                ])
            @endif

        </div>

        {{-- Right Column: Fix Pack + Quick Actions --}}
        <aside class="space-y-6">
            
            {{-- Fix Pack --}}
            @include('scans.partials._fix-pack', [
                'blacklistHits' => $blacklistHits,
                'dmarcPolicy' => $dmarcPolicy,
                'spfLookupCount' => $spfLookupCount,
                'spfSuggestion' => $spfSuggestion,
                'tlsrptOk' => $tlsrptOk,
                'mtastsOk' => $mtastsOk,
                'domain' => $domain,
            ])

            {{-- Quick Actions --}}
            <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
                <div class="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">Quick Actions</div>
                
                {{-- Re-scan selected checks --}}
                <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="space-y-3" x-data="{ dns: true, spf: false, blacklist: true }">
                    @csrf
                    <input type="hidden" name="mode" value="full">
                    
                    <div class="flex flex-wrap gap-2">
                        <label class="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium cursor-pointer transition-colors" :class="dns ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'">
                            <input type="checkbox" x-model="dns" class="sr-only">
                            <span>DNS</span>
                        </label>
                        <label class="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium cursor-pointer transition-colors" :class="spf ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'">
                            <input type="checkbox" x-model="spf" class="sr-only">
                            <span>SPF</span>
                        </label>
                        @if(auth()->user()->can('blacklist', $domain))
                        <label class="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium cursor-pointer transition-colors" :class="blacklist ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'">
                            <input type="checkbox" x-model="blacklist" class="sr-only">
                            <span>Blacklist</span>
                        </label>
                        @endif
                    </div>
                    
                    <button type="submit" class="w-full inline-flex items-center justify-center px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-600 transition-colors">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                        </svg>
                        Re-scan Selected
                    </button>
                </form>

                {{-- Schedule Settings --}}
                <div class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <div class="text-xs text-gray-500 dark:text-gray-400 mb-2">Schedule</div>
                    <div class="text-xs text-gray-600 dark:text-gray-400">
                        Current: <span class="font-medium">{{ ucfirst($cadence) }}</span>
                        <a href="{{ route('automations.index') }}" class="ml-2 text-blue-600 dark:text-blue-400 hover:underline">Manage</a>
                    </div>
                </div>
            </div>

        </aside>

    </div>

    {{-- Back Link --}}
    <div class="pt-6">
        <a href="{{ route('dashboard.domains') }}" class="inline-flex items-center text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200">
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
            </svg>
            Back to Domain Management
        </a>
    </div>

</div>

<script>
    // Copy to clipboard function
    function copyToClipboard(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = button.innerText;
            const originalClasses = button.className;
            button.innerText = 'Copied!';
            button.className = button.className.replace(/bg-\w+-\d+/g, 'bg-green-600').replace(/text-\w+-\d+/g, 'text-white');
            setTimeout(() => {
                button.innerText = originalText;
                button.className = originalClasses;
            }, 1500);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            button.innerText = 'Failed';
            setTimeout(() => {
                button.innerText = 'Copy';
            }, 1500);
        });
    }

    // Download report function
    function downloadReport() {
        const printContent = document.querySelector('.p-6').cloneNode(true);
        
        // Remove interactive elements
        printContent.querySelectorAll('button, form').forEach(el => el.remove());
        printContent.querySelectorAll('[x-data]').forEach(el => {
            el.removeAttribute('x-data');
            el.removeAttribute('@click');
            el.removeAttribute('x-show');
        });
        
        // Create new window for printing
        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <html>
                <head>
                    <title>MXScan Report - {{ $domain->domain }}</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; color: #1f2937; }
                        .bg-green-50 { background-color: #f0fdf4; }
                        .bg-red-50 { background-color: #fef2f2; }
                        .bg-blue-50 { background-color: #eff6ff; }
                        .bg-amber-50 { background-color: #fffbeb; }
                        .text-green-800 { color: #166534; }
                        .text-red-800 { color: #991b1b; }
                        .text-blue-800 { color: #1e40af; }
                        .text-amber-800 { color: #92400e; }
                        .p-4 { padding: 1rem; }
                        .mb-4 { margin-bottom: 1rem; }
                        .rounded-lg { border-radius: 0.5rem; }
                        .border { border: 1px solid #d1d5db; }
                        .font-bold { font-weight: bold; }
                        .text-sm { font-size: 0.875rem; }
                        code { background: #f3f4f6; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
                        h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
                        h2 { font-size: 1.25rem; margin-top: 1.5rem; margin-bottom: 0.75rem; }
                    </style>
                </head>
                <body>
                    <h1>MXScan Report</h1>
                    <p><strong>Domain:</strong> {{ $domain->domain }}</p>
                    <p><strong>Scan Date:</strong> {{ $scan->finished_at?->format('M j, Y \\a\\t g:i A') ?? $scan->created_at->format('M j, Y \\a\\t g:i A') }}</p>
                    <p><strong>Scan ID:</strong> {{ $scan->id }}</p>
                    <hr>
                    ${printContent.innerHTML}
                </body>
            </html>
        `);
        printWindow.document.close();
        setTimeout(() => {
            printWindow.print();
        }, 250);
    }

    // Share report function
    function shareReport() {
        // TODO: Implement tokenized share functionality
        alert('Share functionality coming soon!');
    }
</script>
@endsection
