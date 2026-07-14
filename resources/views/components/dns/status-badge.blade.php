@props([
    'variant' => 'neutral',
    'label',
])

@php
    $classes = match ($variant) {
        'success' => 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-200',
        'warning' => 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200',
        'danger' => 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200',
        'info' => 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200',
        default => 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    };
@endphp

<span {{ $attributes->merge(['class' => "inline-flex shrink-0 items-center rounded px-2 py-0.5 text-xs font-medium {$classes}"]) }}>
    {{ $label }}
</span>
