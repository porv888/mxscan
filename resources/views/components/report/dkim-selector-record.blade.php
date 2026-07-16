@props([
    'selector',
])

@php
    $record = (string) ($selector['record'] ?? '');
    $keyType = strtoupper((string) ($selector['key_type'] ?? 'RSA'));
@endphp

<div class="mx-dkim-record-detail">
    <dl class="mx-dkim-record-meta">
        <div>
            <dt>Selector</dt>
            <dd>{{ $selector['selector'] ?? '—' }}</dd>
        </div>
        <div>
            <dt>Hostname</dt>
            <dd class="font-mono text-[12px]">{{ $selector['host'] ?? '—' }}</dd>
        </div>
        <div>
            <dt>Record type</dt>
            <dd>TXT</dd>
        </div>
        <div>
            <dt>Key algorithm</dt>
            <dd>{{ $keyType }}</dd>
        </div>
        <div>
            <dt>Key length</dt>
            <dd>{{ $selector['key_bits'] ?? '—' }}-bit</dd>
        </div>
    </dl>

    @if($record !== '')
        <div class="mx-dkim-record-value">
            <div class="flex items-center justify-between gap-2">
                <span class="text-xs font-medium uppercase tracking-wide text-gray-500">DNS TXT value</span>
                <x-report.copy-button :value="$record" label="Copy" />
            </div>
            <code class="mt-2 block whitespace-pre-wrap break-all text-[12px] leading-relaxed text-gray-800">{{ $record }}</code>
        </div>
    @else
        <p class="text-[13px] text-gray-500">DKIM record value unavailable for this selector.</p>
    @endif
</div>
