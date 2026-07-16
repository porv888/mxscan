@props([
    'type' => 'TXT',
    'host',
    'value',
    'ttl' => 'Auto',
    'title' => 'DNS record',
    'valueCopyLabel' => 'Copy value',
])

<div {{ $attributes->merge(['class' => 'mx-dns-solution-record']) }}>
    <h5>{{ $title }}</h5>
    <dl class="mx-dns-solution-fields">
        <div><dt>Type</dt><dd>{{ $type }}</dd></div>
        <div><dt>Host</dt><dd><code>{{ $host }}</code></dd></div>
        <div><dt>TTL</dt><dd>{{ $ttl }}</dd></div>
        <div class="mx-dns-solution-value"><dt>Value</dt><dd><code>{{ $value }}</code></dd></div>
    </dl>
    <div class="mx-tech-action-row">
        <x-report.copy-button :value="$host" label="Copy host" class="mx-btn-secondary !static" />
        <x-report.copy-button :value="$value" :label="$valueCopyLabel" class="mx-btn-primary !static" />
        <x-report.copy-button :value="$type . ' ' . $host . ' ' . $value" label="Copy full record" class="mx-btn-secondary !static" />
    </div>
</div>
