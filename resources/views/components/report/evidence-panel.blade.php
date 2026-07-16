@props([
    'split' => false,
    'label' => 'Evidence',
])

<section {{ $attributes->merge(['class' => 'report-evidence-panel mx-evidence-panel mx-tech-evidence-panel']) }} aria-label="{{ $label }}">
    <div class="mx-tech-panel-label">{{ $label }}</div>
    <div @class(['mx-evidence-panel-grid', 'mx-evidence-panel-grid--split' => $split])>
        {{ $slot }}
    </div>
</section>
