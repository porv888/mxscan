@props([
    'id',
    'label',
    'badgeVariant' => 'neutral',
    'badgeLabel',
    'explanation',
    'severity' => 'neutral',
    'primaryAction' => null,
    'open' => false,
    'help' => null,
])

@php
    $accent = match ($severity) {
        'danger' => 'border-l-4 border-red-500',
        'warning' => 'border-l-4 border-amber-500',
        'success' => 'border-l-4 border-green-500/60',
        default => 'border-l-4 border-gray-200 dark:border-gray-600',
    };
@endphp

<details id="{{ $id }}"
         {{ $open ? 'open' : '' }}
         class="group min-w-0 rounded-lg border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800/50 {{ $accent }}">
    <summary class="flex cursor-pointer list-none items-start justify-between gap-3 px-4 py-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-lg [&::-webkit-details-marker]:hidden">
        <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
                <span class="text-sm font-semibold text-gray-900 dark:text-gray-100">{{ $label }}</span>
                @if($help)
                    <x-help-tooltip :title="$help['title']" :text="$help['text']" :impact="$help['impact'] ?? null" :fix="$help['fix'] ?? null" />
                @endif
                <x-dns.status-badge :variant="$badgeVariant" :label="$badgeLabel" />
            </div>
            <p class="mt-1 text-xs leading-5 text-gray-600 dark:text-gray-400">{{ $explanation }}</p>
        </div>
        <div class="flex shrink-0 items-center gap-2">
            @if($primaryAction)
                <a href="{{ $primaryAction['href'] }}"
                   class="mx-btn mx-btn-primary mx-btn-sm hidden sm:inline-flex"
                   onclick="event.stopPropagation()">
                    {{ $primaryAction['label'] }}
                </a>
            @endif
            <svg class="h-4 w-4 text-gray-400 transition-transform group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
            </svg>
        </div>
    </summary>
    <div class="border-t border-gray-100 px-4 py-3 dark:border-gray-700">
        @if($primaryAction)
            <div class="mb-3 sm:hidden">
                <a href="{{ $primaryAction['href'] }}" class="mx-btn mx-btn-primary mx-btn-sm">{{ $primaryAction['label'] }}</a>
            </div>
        @endif
        {{ $slot }}
    </div>
</details>
