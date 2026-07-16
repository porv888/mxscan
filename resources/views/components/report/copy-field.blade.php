@props(['label', 'value', 'copyLabel' => null])

<div class="report-copy-field">
    <span>{{ $label }}</span>
    <code>{{ $value }}</code>
    <x-report.copy-button :value="$value" :label="$copyLabel ?? ('Copy ' . strtolower($label))" class="mx-btn-secondary !static" />
</div>
