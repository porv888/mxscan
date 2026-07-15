@props([
    'value',
    'clamp' => 240,
    'copyLabel' => 'Copy value',
    'recordType' => null,
    'recordHost' => null,
])

<div {{ $attributes->merge(['class' => 'min-w-0 space-y-3']) }}>
    @if($recordType || $recordHost)
        <dl class="grid gap-3 sm:grid-cols-2">
            @if($recordType)
                <div>
                    <dt class="text-xs font-medium text-gray-500">Record type</dt>
                    <dd class="mt-1 text-sm font-medium text-gray-900">{{ $recordType }}</dd>
                </div>
            @endif
            @if($recordHost)
                <div>
                    <dt class="text-xs font-medium text-gray-500">Host</dt>
                    <dd class="mt-1 break-all font-mono text-[13px] text-gray-900">{{ $recordHost }}</dd>
                </div>
            @endif
        </dl>
        <div class="text-xs font-medium text-gray-500">DNS value</div>
    @endif

    <x-report.dns-value-block :value="$value" :clamp="$clamp" />
</div>
