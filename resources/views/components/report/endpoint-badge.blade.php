@props([
    'category',
    'endpoint',
])

<span {{ $attributes->merge(['class' => 'inline-flex items-center gap-1.5 text-xs leading-5 text-gray-500']) }}>
    <span class="font-medium text-gray-600">{{ $category }}</span>
    <span aria-hidden="true" class="text-gray-300">·</span>
    <span class="font-mono text-[12px] text-gray-700">{{ $endpoint }}</span>
</span>
