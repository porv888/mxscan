@props([
    'value',
    'label' => 'Copy',
    'copiedLabel' => 'Copied',
])

<button type="button"
        onclick="copyToClipboard(this.dataset.copyValue, this)"
        {{ $attributes->merge(['class' => 'mx-btn mx-btn-ghost mx-btn-sm mx-dns-value-copy', 'aria-label' => $label]) }}
        data-copy-value="{{ $value }}"
        data-copy-label="{{ $label }}"
        data-copied-label="{{ $copiedLabel }}">
    <i data-lucide="copy" class="h-3.5 w-3.5" aria-hidden="true"></i>
    <span data-copy-text>{{ $label }}</span>
    <span class="sr-only" aria-live="polite" data-copy-feedback></span>
</button>
