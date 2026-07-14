@props([
    'index',
    'rec',
    'expanded' => false,
    'impact' => null,
])

@php
    $severity = $rec['severity'] ?? 'medium';
    $barColor = match ($severity) {
        'critical' => 'bg-red-500',
        'high' => 'bg-amber-500',
        'medium' => 'bg-blue-500',
        default => 'bg-gray-300',
    };
    $badgeVariant = match ($severity) {
        'critical' => 'danger',
        'high' => 'warning',
        'medium' => 'info',
        default => 'neutral',
    };
@endphp

<div class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
    <button type="button"
            @click="toggle({{ $index }})"
            class="flex w-full items-start gap-4 p-4 text-left hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500"
            :aria-expanded="expanded === {{ $index }}">
        <div class="w-1 self-stretch rounded-full {{ $barColor }}"></div>
        <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gray-100 text-sm font-semibold text-gray-700">{{ $index + 1 }}</div>
        <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
                <x-report.status-badge :variant="$badgeVariant" :label="ucfirst($severity)" />
                <h3 class="text-base font-semibold text-gray-900">{{ $rec['title'] }}</h3>
            </div>
            <p class="mt-2 text-sm leading-6 text-gray-600" x-show="expanded !== {{ $index }}">{{ $rec['explanation'] }}</p>
        </div>
        <svg class="mt-1 h-4 w-4 shrink-0 text-gray-400 transition-transform" :class="{ 'rotate-180': expanded === {{ $index }} }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
        </svg>
    </button>

    <div x-show="expanded === {{ $index }}" x-collapse class="border-t border-gray-100 px-4 pb-5 pt-2">
        <div class="pl-6">
            <p class="text-sm leading-6 text-gray-600">{{ $rec['explanation'] }}</p>
            @if($impact)
                <p class="mt-2 text-sm text-gray-500"><span class="font-medium text-gray-700">Impact:</span> {{ $impact }}</p>
            @endif

            @if(!empty($rec['value']))
                <div class="mt-4">
                    <h4 class="text-sm font-semibold text-gray-900">Record to add</h4>
                    <x-report.code-value
                        class="mt-2"
                        :value="$rec['value']"
                        record-type="TXT"
                        :record-host="$rec['record_name'] ?? '@'"
                        :copy-label="'Copy ' . ($rec['title'] ?? 'record')"
                    />
                </div>
            @elseif(($rec['key'] ?? '') === 'blacklist')
                <a href="#tech-blacklist" class="mt-4 inline-flex text-sm font-medium text-blue-700 hover:underline">View blacklist details</a>
            @elseif(!empty($rec['action']))
                <a href="#technical-checks" class="mt-4 inline-flex mx-btn mx-btn-secondary mx-btn-sm">{{ $rec['action'] }}</a>
            @endif
        </div>
    </div>
</div>
