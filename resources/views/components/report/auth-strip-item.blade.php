@props([
    'icon',
    'label',
    'status',
    'explanation',
    'variant' => 'neutral',
])

<div {{ $attributes->merge(['class' => 'flex min-w-0 flex-col gap-2 px-4 py-4 lg:px-5']) }}>
    <div class="flex items-center gap-2">
        <i data-lucide="{{ $icon }}" class="h-4 w-4 text-gray-400" aria-hidden="true"></i>
        <span class="text-base font-medium text-gray-900">{{ $label }}</span>
    </div>
    <x-report.status-badge :variant="$variant" :label="$status" />
    <p class="text-[13px] leading-5 text-gray-500">{{ $explanation }}</p>
</div>
