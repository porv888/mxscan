@props([
    'value',
    'clamp' => 240,
    'copyLabel' => 'Copy value',
    'recordType' => null,
    'recordHost' => null,
])

<div {{ $attributes->merge(['class' => 'min-w-0 space-y-3']) }} x-data="{ expanded: false }">
    @if($recordType || $recordHost)
        <dl class="grid gap-3 sm:grid-cols-3">
            @if($recordType)
                <div>
                    <dt class="text-[13px] font-medium text-gray-500">Type</dt>
                    <dd class="mt-1 text-sm font-medium text-gray-900">{{ $recordType }}</dd>
                </div>
            @endif
            @if($recordHost)
                <div class="sm:col-span-2">
                    <dt class="text-[13px] font-medium text-gray-500">Host</dt>
                    <dd class="mt-1 break-all font-mono text-sm text-gray-900">{{ $recordHost }}</dd>
                </div>
            @endif
        </dl>
        <div>
            <div class="text-[13px] font-medium text-gray-500">Value</div>
        </div>
    @endif

    @php
        $isLong = strlen($value) > $clamp;
        $escaped = e(addslashes($value));
    @endphp

    <div class="min-w-0 overflow-x-auto rounded-lg bg-gray-50 p-3 ring-1 ring-gray-200">
        @if($isLong)
            <code class="block break-all font-mono text-sm text-gray-900 whitespace-pre-wrap" x-show="expanded" x-cloak>{{ $value }}</code>
            <code class="block break-all font-mono text-sm text-gray-900 whitespace-pre-wrap" x-show="!expanded">{{ Str::limit($value, $clamp) }}</code>
            <button type="button" class="mt-2 text-sm font-medium text-blue-700 hover:underline" @click="expanded = !expanded" x-text="expanded ? 'Show less' : 'Show full value'"></button>
        @else
            <code class="block break-all font-mono text-sm text-gray-900 whitespace-pre-wrap">{{ $value }}</code>
        @endif
    </div>

    <button type="button"
            onclick="copyToClipboard('{{ $escaped }}', this)"
            class="mx-btn mx-btn-ghost mx-btn-sm"
            aria-label="{{ $copyLabel }}">
        Copy value
    </button>
</div>
