@props(['label' => 'Re-scan domain'])

<button type="button"
        class="mx-btn mx-btn-primary mx-tech-rescan-button"
        @click="rescan()"
        :disabled="busy || saving">
    <i data-lucide="refresh-cw" class="h-4 w-4" :class="{ 'animate-spin': busy }"></i>
    <span x-text="busy ? 'Scanning…' : @js($label)">{{ $label }}</span>
</button>
