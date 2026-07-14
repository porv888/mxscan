@props([
    'label',
    'earned',
    'possible',
    'status' => 'ok',
])

@php
    $pct = $possible > 0 ? round(($earned / $possible) * 100) : 0;
    $barColor = match (true) {
        $earned >= $possible => 'bg-blue-600',
        $status === 'missing' => 'bg-red-500',
        $status === 'partial' => 'bg-amber-500',
        default => 'bg-gray-300',
    };
    $valueColor = $earned < $possible && $status === 'missing' ? 'text-red-600' : 'text-gray-700';
@endphp

<div {{ $attributes->merge(['class' => 'grid grid-cols-[7rem_1fr_4.5rem] items-center gap-3 py-2']) }}>
    <span class="text-sm font-medium text-gray-900">{{ $label }}</span>
    <div class="h-2 overflow-hidden rounded-full bg-gray-100">
        <div class="h-full rounded-full {{ $barColor }}" style="width: {{ $pct }}%"></div>
    </div>
    <span class="text-right text-sm font-medium {{ $valueColor }}">{{ $earned }} / {{ $possible }}</span>
</div>
