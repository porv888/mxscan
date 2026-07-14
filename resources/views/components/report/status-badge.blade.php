@props([
    'variant' => 'neutral',
    'label',
])

@php
    $classes = match ($variant) {
        'success' => 'bg-green-50 text-green-800 ring-green-600/20',
        'warning' => 'bg-amber-50 text-amber-800 ring-amber-600/20',
        'danger' => 'bg-red-50 text-red-800 ring-red-600/20',
        'info' => 'bg-blue-50 text-blue-800 ring-blue-600/20',
        default => 'bg-gray-100 text-gray-700 ring-gray-500/10',
    };
@endphp

<span {{ $attributes->merge(['class' => "inline-flex shrink-0 items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset {$classes}"]) }}>
    {{ $label }}
</span>
