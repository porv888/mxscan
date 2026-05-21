@props([
    'title',
    'text',
    'impact' => null,
    'fix' => null,
])

<span class="relative inline-flex" x-data="{ open: false }" @click.outside="open = false">
    <button type="button"
            class="inline-flex h-4 w-4 items-center justify-center rounded-full border border-gray-300 text-[10px] font-semibold text-gray-500 hover:border-blue-400 hover:text-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:border-gray-600 dark:text-gray-400 dark:hover:text-blue-300"
            aria-label="Help: {{ $title }}"
            @mouseenter="open = true"
            @mouseleave="open = false"
            @focus="open = true"
            @blur="open = false"
            @click.prevent="open = !open">
        ?
    </button>

    <span x-show="open"
          x-cloak
          x-transition
          role="tooltip"
          class="absolute left-1/2 top-6 z-50 w-72 -translate-x-1/2 rounded-lg border border-gray-200 bg-white p-3 text-left shadow-lg dark:border-gray-700 dark:bg-gray-900">
        <span class="block text-xs font-semibold text-gray-900 dark:text-gray-100">{{ $title }}</span>
        <span class="mt-1 block text-xs leading-5 text-gray-600 dark:text-gray-300">{{ $text }}</span>
        @if($impact)
            <span class="mt-2 block text-xs leading-5 text-amber-700 dark:text-amber-300">{{ $impact }}</span>
        @endif
        @if($fix)
            <span class="mt-2 block text-xs leading-5 text-blue-700 dark:text-blue-300">{{ $fix }}</span>
        @endif
    </span>
</span>
