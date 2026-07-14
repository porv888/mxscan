@props([
    'title' => 'DNS & technical details',
    'helper' => 'Authentication, policy, and transport-security records found during the latest scan.',
    'open' => true,
])

<header class="flex items-start justify-between gap-4">
    <div class="min-w-0">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100">{{ $title }}</h3>
        <p class="mt-1 text-xs leading-5 text-gray-500 dark:text-gray-400">{{ $helper }}</p>
    </div>
    <button type="button"
            @click="sectionOpen = !sectionOpen"
            :aria-expanded="sectionOpen"
            aria-controls="dns-section-body"
            class="mx-btn mx-btn-ghost mx-btn-sm shrink-0">
        <span x-text="sectionOpen ? 'Collapse section' : 'Expand section'"></span>
        <svg class="h-4 w-4 transition-transform" :class="{ 'rotate-180': sectionOpen }" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
        </svg>
    </button>
</header>
