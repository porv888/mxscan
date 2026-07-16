@props([
    'title' => 'How to fix',
])

<section {{ $attributes->merge(['class' => 'report-solution-panel mx-tech-solution-panel']) }} aria-label="{{ $title }}">
    <div class="mx-tech-panel-label">{{ $title }}</div>
    {{ $slot }}
</section>
