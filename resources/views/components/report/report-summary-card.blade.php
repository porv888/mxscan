@props([
    'icon',
    'label',
    'status',
    'explanation',
    'variant' => 'neutral',
    'target',
    'score' => null,
])

<a href="#{{ $target }}"
   class="report-summary-card report-summary-card--{{ $variant }}"
   onclick="const el = document.getElementById('{{ $target }}'); if (el) { el.open = true; }"
   aria-label="{{ $label }}: {{ $status }}. View technical check">
    <span class="report-summary-icon" aria-hidden="true"><i data-lucide="{{ $icon }}"></i></span>
    <span class="report-summary-content">
        <span class="report-summary-label">{{ $label }}</span>
        <x-report.status-pill :variant="$variant" :label="$status" />
        <span class="report-summary-evidence">{{ $explanation }}</span>
        @if(is_array($score) && isset($score['earned'], $score['possible']))
            <span class="report-summary-score">
                {{ $score['earned'] }}/{{ $score['possible'] }} points
                @if($score['earned'] < $score['possible'] && $variant !== 'success')
                    · −{{ $score['possible'] - $score['earned'] }} points
                @endif
            </span>
        @endif
    </span>
</a>
