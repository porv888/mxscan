@props([
    'split' => false,
])

<div {{ $attributes->merge(['class' => 'mx-evidence-panel']) }}>
    <div @class(['mx-evidence-panel-grid', 'mx-evidence-panel-grid--split' => $split])>
        {{ $slot }}
    </div>
</div>
