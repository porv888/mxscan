{{-- DNS Security Section - Auto-collapse when all green --}}
@php
    $mxData = $records['MX'] ?? null;
    $spfData = $records['SPF'] ?? null;
    $dmarcData = $records['DMARC'] ?? null;
    $tlsrptData = $records['TLS-RPT'] ?? null;
    $mtastsData = $records['MTA-STS'] ?? null;
    
    $allGreen = $mxData && $mxData['status'] === 'found' &&
                $spfData && $spfData['status'] === 'found' &&
                $dmarcData && $dmarcData['status'] === 'found' &&
                $tlsrptData && $tlsrptData['status'] === 'found' &&
                $mtastsData && $mtastsData['status'] === 'found';
@endphp

<section class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6" x-data="{ open: {{ $allGreen ? 'false' : 'true' }} }">
    <header class="flex items-center justify-between mb-4">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">DNS Security</h3>
        <button @click="open=!open" class="text-sm text-blue-700 dark:text-blue-300 hover:underline flex items-center gap-1">
            <span x-show="!open">Show Details</span>
            <span x-show="open" x-cloak>Hide Details</span>
            <svg class="w-4 h-4 transition-transform" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
            </svg>
        </button>
    </header>

    @if($allGreen && !$open)
        <div class="text-sm text-green-700 dark:text-green-300">✓ All configured. Great job!</div>
    @endif

    <div x-show="open" x-collapse class="space-y-4">
        {{-- MX Records --}}
        <div>
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">MX Records</h3>
                @if($mxData && $mxData['status'] === 'found')
                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                    </svg>
                    Configured
                </span>
                @endif
            </div>
            @if($mxData && $mxData['status'] === 'found')
            <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                @if(is_array($mxData['data']))
                    @foreach($mxData['data'] as $mx)
                    <div class="flex justify-between items-center text-sm mb-1 last:mb-0">
                        <span class="text-gray-900 dark:text-gray-100">Priority {{ $mx['pri'] ?? 'N/A' }}: <code class="text-xs bg-white dark:bg-gray-800 px-1 py-0.5 rounded">{{ $mx['target'] ?? 'Unknown' }}</code></span>
                        <span class="text-xs text-gray-500 dark:text-gray-400">TTL: {{ $mx['ttl'] ?? 'N/A' }}s</span>
                    </div>
                    @endforeach
                @else
                    <span class="text-sm text-gray-900 dark:text-gray-100">{{ $mxData['data'] }}</span>
                @endif
            </div>
            @else
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <div class="flex items-center text-sm text-red-800 dark:text-red-200">
                    <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                    </svg>
                    No MX records found
                </div>
            </div>
            @endif
        </div>

        {{-- SPF Record --}}
        <div>
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">SPF Record</h3>
                @if($spfData && $spfData['status'] === 'found')
                <div class="flex items-center gap-2">
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                        <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                        </svg>
                        Found
                    </span>
                    @if($spfLookupCount)
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium {{ $spfLookupCount >= 10 ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' : ($spfLookupCount >= 7 ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200' : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200') }}">
                        {{ $spfLookupCount }}/10 lookups
                    </span>
                    @endif
                </div>
                @endif
            </div>
            @if($spfData && $spfData['status'] === 'found')
            <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                <div class="flex justify-between items-start">
                    <code class="text-xs text-gray-900 dark:text-gray-100 break-all flex-1">{{ $spfData['data'] }}</code>
                    <div class="flex gap-1 ml-3 flex-shrink-0">
                        <button onclick="copyToClipboard('{{ addslashes($spfData['data']) }}', this)" class="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-50 dark:bg-gray-700 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-600">
                            Copy
                        </button>
                        @if($spfLookupCount >= 7)
                        <a href="{{ route('spf.show', $domain) }}" class="px-2 py-1 text-xs font-medium text-blue-700 bg-blue-50 rounded hover:bg-blue-100 dark:bg-blue-900 dark:text-blue-200 dark:hover:bg-blue-800">
                            Optimize
                        </a>
                        @endif
                    </div>
                </div>
            </div>
            @else
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <div class="flex items-center text-sm text-red-800 dark:text-red-200">
                    <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                    </svg>
                    No SPF record found
                </div>
            </div>
            @endif
        </div>

        {{-- DMARC Policy --}}
        <div>
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">DMARC Policy</h3>
                @if($dmarcData && $dmarcData['status'] === 'found')
                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                    </svg>
                    Configured
                </span>
                @endif
            </div>
            @if($dmarcData && $dmarcData['status'] === 'found')
            <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                <div class="flex justify-between items-start">
                    <code class="text-xs text-gray-900 dark:text-gray-100 break-all flex-1">{{ $dmarcData['data'] }}</code>
                    <button onclick="copyToClipboard('{{ addslashes($dmarcData['data']) }}', this)" class="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-50 dark:bg-gray-700 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-600 ml-3 flex-shrink-0">
                        Copy
                    </button>
                </div>
            </div>
            @else
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <div class="flex items-center text-sm text-red-800 dark:text-red-200">
                    <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                    </svg>
                    No DMARC policy found
                </div>
            </div>
            @endif
        </div>

        {{-- TLS-RPT --}}
        <div>
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">TLS-RPT</h3>
                @if($tlsrptData && $tlsrptData['status'] === 'found')
                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                    </svg>
                    Configured
                </span>
                @endif
            </div>
            @if($tlsrptData && $tlsrptData['status'] === 'found')
            <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                <div class="flex justify-between items-start">
                    <code class="text-xs text-gray-900 dark:text-gray-100 break-all flex-1">{{ $tlsrptData['data'] }}</code>
                    <button onclick="copyToClipboard('{{ addslashes($tlsrptData['data']) }}', this)" class="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-50 dark:bg-gray-700 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-600 ml-3 flex-shrink-0">
                        Copy
                    </button>
                </div>
            </div>
            @else
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <div class="flex items-center justify-between">
                    <div class="flex items-center text-sm text-red-800 dark:text-red-200">
                        <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                        </svg>
                        No TLS-RPT record found
                    </div>
                    <a href="#fix-pack" class="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline">Add Now</a>
                </div>
            </div>
            @endif
        </div>

        {{-- MTA-STS --}}
        <div>
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">MTA-STS</h3>
                @if($mtastsData && $mtastsData['status'] === 'found')
                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                    </svg>
                    Configured
                </span>
                @endif
            </div>
            @if($mtastsData && $mtastsData['status'] === 'found')
            <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                <div class="flex justify-between items-start">
                    <code class="text-xs text-gray-900 dark:text-gray-100 break-all flex-1">{{ $mtastsData['data'] }}</code>
                    <button onclick="copyToClipboard('{{ addslashes($mtastsData['data']) }}', this)" class="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-50 dark:bg-gray-700 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-600 ml-3 flex-shrink-0">
                        Copy
                    </button>
                </div>
            </div>
            @else
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <div class="flex items-center justify-between">
                    <div class="flex items-center text-sm text-red-800 dark:text-red-200">
                        <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                        </svg>
                        No MTA-STS policy found
                    </div>
                    <a href="#fix-pack" class="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline">Add Now</a>
                </div>
            </div>
            @endif
        </div>
    </div>
</section>
