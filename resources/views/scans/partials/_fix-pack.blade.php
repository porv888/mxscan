{{-- Fix Pack — renders recommendations from ScanRecommendationService only --}}
@php
    $coreRecs = collect($recommendations ?? [])->reject(fn ($r) => ($r['severity'] ?? '') === 'optional')->values();
    $optionalRecs = collect($recommendations ?? [])->where('severity', 'optional')->values();
    $clearState = $allClear['state'] ?? 'needs_fixes';
@endphp
<div id="fix-pack" class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
    <h2 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Recommended Fixes</h2>
    
    <div class="space-y-4">
        @foreach($coreRecs as $index => $rec)
            @php
                $badgeClass = match($rec['severity'] ?? 'medium') {
                    'critical' => 'bg-red-100 text-red-600 dark:bg-red-900/50 dark:text-red-400',
                    'high' => 'bg-amber-100 text-amber-600 dark:bg-amber-900/50 dark:text-amber-400',
                    'medium' => 'bg-blue-100 text-blue-600 dark:bg-blue-900/50 dark:text-blue-400',
                    default => 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
                };
            @endphp
            <div class="pb-4 {{ !$loop->last ? 'border-b border-gray-200 dark:border-gray-700' : '' }}">
                <div class="flex items-start mb-3">
                    <div class="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center mr-3 {{ $badgeClass }}">
                        <span class="text-sm font-bold">{{ $index + 1 }}</span>
                    </div>
                    <div class="flex-1">
                        <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">{{ $rec['title'] }}</h3>
                        <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">{{ $rec['explanation'] }}</p>
                        @if(!empty($rec['value']))
                            <x-copy-row
                                :label="($rec['record_name'] ?? null) ? (($rec['action'] ?? 'Record') . ' (' . $rec['record_name'] . ')') : ($rec['action'] ?? 'Copy value')"
                                :value="$rec['value']"
                            />
                        @elseif(($rec['key'] ?? '') === 'blacklist')
                            <a href="#blacklist-section" class="inline-flex items-center px-3 py-1.5 text-xs font-medium text-white bg-red-600 rounded-md hover:bg-red-700 transition-colors">
                                {{ $rec['action'] ?? 'View delist links' }}
                            </a>
                        @endif
                    </div>
                </div>
            </div>
        @endforeach

        @if($clearState === 'all_clear')
        <div class="text-center py-8">
            <svg class="w-16 h-16 mx-auto text-green-500 dark:text-green-400 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-1">All Clear!</h3>
            <p class="text-sm text-gray-600 dark:text-gray-400">{{ $allClear['message'] ?? 'No critical fixes needed.' }}</p>
        </div>
        @elseif($clearState === 'partial_clear')
        <div class="rounded-lg border border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-900/20 p-4 text-sm text-blue-900 dark:text-blue-100">
            {{ $allClear['message'] }}
        </div>
        @endif

        @if($optionalRecs->isNotEmpty())
            <div class="pt-2 border-t border-gray-100 dark:border-gray-700">
                <p class="text-xs font-medium text-gray-500 mb-2">Optional</p>
                @foreach($optionalRecs as $rec)
                    <p class="text-xs text-gray-600 dark:text-gray-400 mb-1">{{ $rec['title'] }} — {{ $rec['explanation'] }}</p>
                @endforeach
            </div>
        @endif
    </div>
</div>

{{-- Renewal Reminders Card --}}
<div class="mt-6 rounded-xl border border-gray-200 dark:border-gray-700 p-4 bg-white dark:bg-gray-800">
    <div class="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">Renewal Reminders</div>
    <ul class="text-sm text-gray-600 dark:text-gray-300 space-y-2">
        <li class="flex items-center justify-between">
            <span>Domain:</span>
            <span class="font-medium {{ ($domainDays ?? 0) < 7 ? 'text-red-600 dark:text-red-400' : (($domainDays ?? 0) < 30 ? 'text-amber-600 dark:text-amber-400' : 'text-green-700 dark:text-green-300') }}">
                {{ $domainDays !== null ? $domainDays.' days' : 'unknown' }}
            </span>
        </li>
        <li class="flex items-center justify-between">
            <span>SSL:</span>
            <span class="font-medium {{ ($sslDays ?? 0) < 7 ? 'text-red-600 dark:text-red-400' : (($sslDays ?? 0) < 30 ? 'text-amber-600 dark:text-amber-400' : 'text-green-700 dark:text-green-300') }}">
                {{ $sslDays !== null ? $sslDays.' days' : 'unknown' }}
            </span>
        </li>
    </ul>
    <a href="{{ route('domains.hub.settings', $domain) }}#renewals" class="mt-3 inline-block text-xs text-blue-700 dark:text-blue-300 underline hover:no-underline">Edit dates</a>
</div>
