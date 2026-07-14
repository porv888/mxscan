@props([
    'score',
    'percent',
    'label',
    'supporting',
    'subtitle',
    'delta' => null,
])

@php
    $radius = 72;
    $circumference = 2 * M_PI * $radius;
    $offset = $circumference - ($circumference * max(0, min(100, $percent)) / 100);
@endphp

<div {{ $attributes->merge(['class' => 'flex flex-col items-center text-center lg:items-start lg:text-left']) }}>
    <div class="relative h-44 w-44">
        <svg class="h-full w-full -rotate-90" viewBox="0 0 180 180" aria-hidden="true">
            <circle cx="90" cy="90" r="{{ $radius }}" fill="none" stroke="#e5e7eb" stroke-width="12"></circle>
            <circle cx="90" cy="90" r="{{ $radius }}" fill="none" stroke="#2563eb" stroke-width="12"
                    stroke-linecap="round"
                    stroke-dasharray="{{ $circumference }}"
                    stroke-dashoffset="{{ $offset }}"></circle>
        </svg>
        <div class="absolute inset-0 flex flex-col items-center justify-center">
            <div class="text-6xl font-bold leading-none text-gray-900">{{ $score ?? '—' }}</div>
            <div class="mt-1 text-lg text-gray-500">/100</div>
        </div>
    </div>

    <div class="mt-4 space-y-1">
        <div class="flex flex-wrap items-center justify-center gap-2 lg:justify-start">
            <p class="text-base font-semibold text-gray-900">{{ $label }}</p>
            @if($delta !== null)
                <span class="rounded-md px-2 py-0.5 text-xs font-medium {{ $delta >= 0 ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800' }}">
                    {{ $delta >= 0 ? '+' : '' }}{{ $delta }}
                </span>
            @endif
        </div>
        <p class="text-sm text-gray-600">{{ $supporting }}</p>
        <p class="text-[13px] text-gray-500">{{ $subtitle }}</p>
    </div>
</div>
