@props([
    'type' => 'TXT',
    'host',
    'value',
    'ttl' => 'Auto',
    'title' => 'Generated DNS record',
    'valueCopyLabel' => 'Copy value',
])

<x-report.dns-solution-record
    :type="$type"
    :host="$host"
    :value="$value"
    :ttl="$ttl"
    :title="$title"
    :value-copy-label="$valueCopyLabel"
    class="report-generated-record"
/>
