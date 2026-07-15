@props([
    'value',
    'clamp' => 320,
])

@php
    $isLong = strlen($value) > $clamp;
@endphp

<div {{ $attributes->merge(['class' => 'mx-dns-value-block']) }} x-data="{ expanded: {{ $isLong ? 'false' : 'true' }} }">
    @if($isLong)
        <code x-show="expanded" x-cloak>{{ $value }}</code>
        <code x-show="!expanded">{{ Str::limit($value, $clamp) }}</code>
        <button type="button"
                class="mt-2 text-xs font-medium text-blue-700 hover:underline"
                @click="expanded = !expanded"
                x-text="expanded ? 'Show less' : 'Show full value'"></button>
    @else
        <code>{{ $value }}</code>
    @endif

    <x-report.copy-button :value="$value" />
</div>
