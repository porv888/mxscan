@props([
    'id',
    'icon',
    'label',
    'badgeVariant' => 'neutral',
    'badgeLabel',
    'result',
    'action' => null,
    'open' => false,
])

<details id="{{ $id }}" {{ $open ? 'open' : '' }} class="group border-b border-gray-200 last:border-b-0">
    <summary class="flex cursor-pointer list-none items-center gap-3 px-4 py-3.5 hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500 [&::-webkit-details-marker]:hidden">
        <i data-lucide="{{ $icon }}" class="h-4 w-4 shrink-0 text-gray-400" aria-hidden="true"></i>
        <span class="w-28 shrink-0 text-sm font-medium text-gray-900 sm:w-32">{{ $label }}</span>
        <x-report.status-badge :variant="$badgeVariant" :label="$badgeLabel" class="hidden sm:inline-flex" />
        <span class="min-w-0 flex-1 truncate text-sm text-gray-600">{{ $result }}</span>
        @if($action)
            <span class="hidden text-sm font-medium text-blue-700 sm:inline">{{ $action['label'] }}</span>
        @endif
        <svg class="h-4 w-4 shrink-0 text-gray-400 transition-transform group-open:rotate-90" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
        </svg>
    </summary>
    <div class="border-t border-gray-100 bg-gray-50/40 px-4 py-4">
        {{ $slot }}
    </div>
</details>
