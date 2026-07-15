@props([
    'severity' => 'medium',
])

@php
    $label = ucfirst($severity);
    $variant = match ($severity) {
        'critical' => 'danger',
        'high' => 'warning',
        'medium' => 'info',
        'low', 'optional' => 'neutral',
        default => 'neutral',
    };
@endphp

<x-report.status-pill :variant="$variant" :label="$label" {{ $attributes }} />
