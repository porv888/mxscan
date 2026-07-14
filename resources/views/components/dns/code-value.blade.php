@props([
    'value',
    'clamp' => 200,
    'copyLabel' => 'Copy record',
])

@php
    $isLong = strlen($value) > $clamp;
    $escaped = e(addslashes($value));
@endphp

<div {{ $attributes->merge(['class' => 'min-w-0 space-y-2']) }} x-data="{ expanded: false }">
    <div class="min-w-0 overflow-x-auto rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-700 dark:bg-gray-900/50">
        @if($isLong)
            <code class="block break-all font-mono text-xs text-gray-900 dark:text-gray-100 whitespace-pre-wrap" x-show="expanded" x-cloak>{{ $value }}</code>
            <code class="block break-all font-mono text-xs text-gray-900 dark:text-gray-100 whitespace-pre-wrap" x-show="!expanded">{{ Str::limit($value, $clamp) }}</code>
            <button type="button"
                    class="mt-2 text-xs font-medium text-blue-700 hover:underline dark:text-blue-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
                    @click="expanded = !expanded"
                    x-text="expanded ? 'Show less' : 'Show full value'">
            </button>
        @else
            <code class="block break-all font-mono text-xs text-gray-900 dark:text-gray-100 whitespace-pre-wrap">{{ $value }}</code>
        @endif
    </div>
    <button type="button"
            onclick="copyToClipboard('{{ $escaped }}', this)"
            class="mx-btn mx-btn-ghost mx-btn-sm"
            aria-label="{{ $copyLabel }}">
        Copy
    </button>
</div>
