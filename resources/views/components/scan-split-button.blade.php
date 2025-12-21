@props([
    'domain',
    'canBlacklist' => true,
])

<div x-data="{ open: false }" class="relative inline-flex">
    {{-- Primary Button: Full Scan (Synchronous) --}}
    <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="inline">
        @csrf
        <input type="hidden" name="mode" value="full">
        <button
            type="submit"
            class="inline-flex items-center px-3 py-1 text-xs font-medium text-white bg-blue-600 border border-blue-600 rounded-l hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1"
        >
            <i data-lucide="search" class="w-3 h-3 mr-1"></i>
            <span class="hidden lg:inline">Scan</span>
        </button>
    </form>

    {{-- Toggle Button --}}
    <button 
        type="button"
        class="inline-flex items-center px-2 py-1 text-xs font-medium text-white bg-blue-600 border border-l-0 border-blue-600 rounded-r hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1"
        @click="open = !open" 
        aria-haspopup="menu" 
        :aria-expanded="open"
    >
        <i data-lucide="chevron-down" class="w-3 h-3"></i>
    </button>

    {{-- Dropdown Menu --}}
    <div
        x-cloak
        x-show="open"
        x-transition:enter="transition ease-out duration-100"
        x-transition:enter-start="transform opacity-0 scale-95"
        x-transition:enter-end="transform opacity-100 scale-100"
        x-transition:leave="transition ease-in duration-75"
        x-transition:leave-start="transform opacity-100 scale-100"
        x-transition:leave-end="transform opacity-0 scale-95"
        @click.away="open = false"
        class="absolute right-0 z-20 mt-2 w-48 bg-white border border-gray-200 rounded-md shadow-lg"
        role="menu" 
        aria-label="Scan options"
    >
        {{-- DNS Only --}}
        <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="block" role="none">
            @csrf
            <input type="hidden" name="mode" value="dns">
            <button 
                type="submit" 
                class="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 focus:outline-none focus:bg-gray-50" 
                role="menuitem"
            >
                <i data-lucide="globe" class="w-4 h-4 mr-2 text-blue-500"></i>
                DNS only
            </button>
        </form>

        {{-- SPF Only --}}
        <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="block" role="none">
            @csrf
            <input type="hidden" name="mode" value="spf">
            <button 
                type="submit" 
                class="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 focus:outline-none focus:bg-gray-50" 
                role="menuitem"
            >
                <i data-lucide="shield" class="w-4 h-4 mr-2 text-purple-500"></i>
                SPF only
            </button>
        </form>

        {{-- Blacklist Only (Plan Gated) --}}
        @if($canBlacklist)
            <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="block" role="none">
                @csrf
                <input type="hidden" name="mode" value="blacklist">
                <button 
                    type="submit" 
                    class="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 focus:outline-none focus:bg-gray-50" 
                    role="menuitem"
                >
                    <i data-lucide="shield-check" class="w-4 h-4 mr-2 text-orange-500"></i>
                    Blacklist only
                </button>
            </form>
        @else
            <button 
                type="button" 
                class="flex items-center w-full px-4 py-2 text-sm text-gray-400 cursor-not-allowed" 
                role="menuitem"
                @click.prevent="$dispatch('open-upgrade')"
            >
                <i data-lucide="lock" class="w-4 h-4 mr-2 text-amber-500"></i>
                Blacklist only 
                <span class="ml-auto text-xs bg-amber-100 text-amber-800 px-2 py-0.5 rounded-full">Upgrade</span>
            </button>
        @endif

        {{-- Divider --}}
        <div class="border-t border-gray-100"></div>

        {{-- SPF Optimizer Link --}}
        <a 
            href="{{ route('spf.show', $domain->domain) }}" 
            class="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 focus:outline-none focus:bg-gray-50"
            role="menuitem"
        >
            <i data-lucide="settings" class="w-4 h-4 mr-2 text-gray-500"></i>
            SPF Optimizer
        </a>
    </div>
</div>
