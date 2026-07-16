@props(['label', 'variant' => 'opportunity'])

<span {{ $attributes->merge(['class' => 'report-score-impact report-score-impact--' . $variant]) }}>
    {{ $label }}
</span>
