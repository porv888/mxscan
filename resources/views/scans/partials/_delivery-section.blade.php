{{-- Delivery Monitoring Section - Last 5 checks --}}
@if($deliveries->count() > 0)
<div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
    <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-gray-100">Recent Delivery Tests</h2>
        <a href="{{ route('delivery.index', $domain) }}" class="text-sm text-blue-600 dark:text-blue-400 hover:underline">View All</a>
    </div>

    <div class="space-y-3">
        @foreach($deliveries as $delivery)
        <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-900/50 transition-colors cursor-pointer" 
             x-data="{ showDetails: false }"
             @click="showDetails = !showDetails">
            
            {{-- Summary Row --}}
            <div class="flex items-center justify-between">
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-3 mb-1">
                        <span class="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                            From: {{ $delivery->from_address ?? 'Unknown' }}
                        </span>
                        
                        {{-- TTI Chip --}}
                        @if($delivery->time_to_inbox)
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium {{ $delivery->time_to_inbox < 5 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : ($delivery->time_to_inbox < 30 ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200' : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200') }}">
                            TTI: {{ $delivery->time_to_inbox }}s
                        </span>
                        @endif
                    </div>
                    
                    <div class="text-xs text-gray-500 dark:text-gray-400 truncate">
                        Subject: {{ $delivery->subject ?? 'No subject' }}
                    </div>
                </div>
                
                {{-- Auth Icons --}}
                <div class="flex items-center gap-2 ml-4">
                    @if($delivery->spf_pass)
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" title="SPF Passed">
                        SPF ✓
                    </span>
                    @else
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200" title="SPF Failed">
                        SPF ✗
                    </span>
                    @endif
                    
                    @if($delivery->dkim_pass)
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" title="DKIM Passed">
                        DKIM ✓
                    </span>
                    @else
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200" title="DKIM Failed">
                        DKIM ✗
                    </span>
                    @endif
                    
                    @if($delivery->dmarc_pass)
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" title="DMARC Passed">
                        DMARC ✓
                    </span>
                    @else
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200" title="DMARC Failed">
                        DMARC ✗
                    </span>
                    @endif
                    
                    <svg class="w-4 h-4 text-gray-400 dark:text-gray-500 transition-transform" :class="{ 'rotate-180': showDetails }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </div>
            </div>

            {{-- Details Drawer --}}
            <div x-show="showDetails" x-collapse class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                {{-- Analysis First --}}
                <div class="mb-4">
                    <h4 class="text-xs font-semibold text-gray-900 dark:text-gray-100 mb-2">Analysis</h4>
                    <div class="space-y-2 text-sm">
                        <div class="flex justify-between">
                            <span class="text-gray-600 dark:text-gray-400">Received:</span>
                            <span class="text-gray-900 dark:text-gray-100">{{ $delivery->created_at->format('M j, Y H:i:s') }}</span>
                        </div>
                        @if($delivery->time_to_inbox)
                        <div class="flex justify-between">
                            <span class="text-gray-600 dark:text-gray-400">Time to Inbox:</span>
                            <span class="text-gray-900 dark:text-gray-100">{{ $delivery->time_to_inbox }}s</span>
                        </div>
                        @endif
                        @if($delivery->folder)
                        <div class="flex justify-between">
                            <span class="text-gray-600 dark:text-gray-400">Folder:</span>
                            <span class="text-gray-900 dark:text-gray-100">{{ $delivery->folder }}</span>
                        </div>
                        @endif
                    </div>
                </div>

                {{-- Raw Headers Toggle --}}
                <div x-data="{ showHeaders: false }">
                    <button @click="showHeaders = !showHeaders" class="text-xs text-blue-600 dark:text-blue-400 hover:underline flex items-center">
                        <svg class="w-4 h-4 mr-1 transition-transform" :class="{ 'rotate-90': showHeaders }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                        <span x-text="showHeaders ? 'Hide' : 'Show'"></span> Raw Headers
                    </button>
                    
                    <div x-show="showHeaders" x-collapse class="mt-2">
                        <pre class="text-xs bg-gray-50 dark:bg-gray-900 p-3 rounded border border-gray-200 dark:border-gray-700 overflow-x-auto">{{ $delivery->raw_headers ?? 'No headers available' }}</pre>
                    </div>
                </div>
            </div>
        </div>
        @endforeach
    </div>
</div>
@endif
