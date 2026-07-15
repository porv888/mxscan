@props([
    'variant' => 'neutral',
    'label',
    'showDot' => true,
])

@php
    $modifier = match ($variant) {
        'success' => 'mx-status-pill--success',
        'warning' => 'mx-status-pill--warning',
        'danger' => 'mx-status-pill--danger',
        'info' => 'mx-status-pill--info',
        default => 'mx-status-pill--neutral',
    };
@endphp

<span {{ $attributes->merge(['class' => "mx-status-pill {$modifier}", 'role' => 'status']) }}>
    @if($showDot)
        <span class="mx-status-pill-dot" aria-hidden="true"></span>
    @endif
    <span>{{ $label }}</span>
</span>
