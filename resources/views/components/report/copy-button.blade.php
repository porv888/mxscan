@props([
    'value',
    'label' => 'Copy',
    'copiedLabel' => 'Copied',
])

<button type="button"
        onclick="copyToClipboard('{{ e(addslashes($value)) }}', this)"
        {{ $attributes->merge(['class' => 'mx-btn mx-btn-ghost mx-btn-sm mx-dns-value-copy', 'aria-label' => $label]) }}
        data-copy-label="{{ $label }}"
        data-copied-label="{{ $copiedLabel }}">
    <i data-lucide="copy" class="h-3.5 w-3.5" aria-hidden="true"></i>
    <span class="sr-only">{{ $label }}</span>
</button>
