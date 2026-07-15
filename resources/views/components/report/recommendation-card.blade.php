@props([
    'index',
    'rec',
    'impact' => null,
    'category' => null,
    'endpoint' => null,
    'scoreOpportunity' => null,
])

@php
    $severity = $rec['severity'] ?? 'medium';
    $cardModifier = match ($severity) {
        'critical' => 'mx-recommendation-card--critical',
        'high' => 'mx-recommendation-card--high',
        default => '',
    };
@endphp

<article class="mx-recommendation-card {{ $cardModifier }}" data-recommendation-card>
    <button type="button"
            @click="toggle({{ $index }})"
            class="mx-recommendation-card-header"
            :aria-expanded="expanded === {{ $index }}"
            aria-controls="rec-panel-{{ $index }}">
        <div class="flex flex-col gap-1.5 sm:flex-row sm:items-center">
            <span class="mx-recommendation-priority" aria-label="Priority {{ $index + 1 }}">{{ $index + 1 }}</span>
            <x-report.severity-badge :severity="$severity" class="w-fit" />
        </div>

        <div class="min-w-0">
            <h3 class="text-[15px] font-semibold leading-[1.35] text-gray-900">{{ $rec['title'] }}</h3>

            @if($endpoint)
                <x-report.endpoint-badge
                    :category="$endpoint['category']"
                    :endpoint="$endpoint['endpoint']"
                    class="mt-1"
                />
            @elseif($category)
                <p class="mt-1 text-xs leading-5 text-gray-500">{{ $category }}</p>
            @endif

            <p class="mt-1.5 line-clamp-2 text-[13px] leading-[1.5] text-gray-600" x-show="expanded !== {{ $index }}">
                {{ $rec['explanation'] }}
            </p>

            @if($scoreOpportunity)
                <p class="mt-1 text-xs leading-5 text-gray-500">{{ $scoreOpportunity }}</p>
            @endif
        </div>

        <div class="flex flex-col items-end justify-between gap-2 self-stretch sm:min-w-[7.5rem]">
            @if(!empty($rec['action']))
                <span class="hidden text-sm font-medium text-blue-700 sm:inline">{{ $rec['action'] }}</span>
            @endif
            <svg class="h-5 w-5 shrink-0 text-gray-400 transition-transform duration-175"
                 :class="{ 'rotate-180': expanded === {{ $index }} }"
                 fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
            </svg>
        </div>
    </button>

    <div id="rec-panel-{{ $index }}"
         x-show="expanded === {{ $index }}"
         x-collapse
         class="mx-recommendation-expanded"
         role="region"
         aria-label="{{ $rec['title'] }} details">
        <div class="space-y-4 pt-3">
            <div>
                <h4 class="text-sm font-semibold text-gray-900">Why this matters</h4>
                <p class="mt-1 text-[13px] leading-[1.5] text-gray-600">{{ $rec['explanation'] }}</p>
                @if($impact)
                    <p class="mt-2 text-[13px] leading-[1.5] text-gray-500">{{ $impact }}</p>
                @endif
            </div>

            @if(!empty($rec['value']))
                <div>
                    <h4 class="text-sm font-semibold text-gray-900">Evidence</h4>
                    <div class="mt-2">
                        <x-report.code-value
                            :value="$rec['value']"
                            record-type="TXT"
                            :record-host="$rec['record_name'] ?? '@'"
                            :copy-label="'Copy ' . ($rec['title'] ?? 'record')"
                        />
                    </div>
                </div>

                <div>
                    <h4 class="text-sm font-semibold text-gray-900">How to fix</h4>
                    <p class="mt-1 text-[13px] leading-[1.5] text-gray-600">Add the record below at your DNS provider, then re-scan to verify.</p>
                    <div class="mt-3 flex flex-wrap items-center gap-3">
                        @if(!empty($rec['action']))
                            <span class="mx-btn mx-btn-primary mx-btn-sm">{{ $rec['action'] }}</span>
                        @endif
                        <a href="#technical-checks" class="text-sm font-medium text-blue-700 hover:underline">View technical evidence</a>
                    </div>
                </div>
            @else
                <div>
                    <h4 class="text-sm font-semibold text-gray-900">How to fix</h4>
                    @if(($rec['key'] ?? '') === 'blacklist')
                        <a href="#tech-blacklist" class="mt-2 inline-flex min-h-[44px] items-center text-sm font-medium text-blue-700 hover:underline">View blacklist details</a>
                    @elseif(!empty($rec['action']))
                        <div class="mt-3 flex flex-wrap items-center gap-3">
                            <a href="#technical-checks" class="mx-btn mx-btn-secondary mx-btn-sm min-h-[44px]">{{ $rec['action'] }}</a>
                            <a href="#technical-checks" class="text-sm font-medium text-blue-700 hover:underline">View technical evidence</a>
                        </div>
                    @endif
                </div>
            @endif
        </div>
    </div>
</article>
