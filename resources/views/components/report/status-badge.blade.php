@props([
    'variant' => 'neutral',
    'label',
])

<x-report.status-pill :variant="$variant" :label="$label" {{ $attributes }} />
