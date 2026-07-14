@props([
    'domain',
    'scan',
    'scanUrl',
])

@php
    $scannedAt = $scan->finished_at?->timezone(auth()->user()->timezone ?? 'UTC')->format('j F Y \a\t H:i')
        ?? $scan->created_at->timezone(auth()->user()->timezone ?? 'UTC')->format('j F Y \a\t H:i');
@endphp

<header class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
    <div class="min-w-0">
        <h1 class="text-3xl font-semibold tracking-tight text-gray-900">{{ $domain->domain }}</h1>
        <p class="mt-1 text-sm text-gray-600 lg:text-base">
            Email security report · Scanned {{ $scannedAt }}
        </p>
    </div>
    <div class="flex w-full flex-wrap gap-2 sm:w-auto sm:justify-end">
        <button type="button" onclick="shareReport()" class="mx-btn mx-btn-secondary flex-1 sm:flex-none">
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.367 2.684 3 3 0 00-5.367-2.684z"></path>
            </svg>
            Share
        </button>
        <form method="POST" action="{{ $scanUrl }}">
            @csrf
            <input type="hidden" name="mode" value="full">
            <button type="submit" class="mx-btn mx-btn-secondary flex-1 sm:flex-none">
                <i data-lucide="scan" class="h-4 w-4"></i>
                Scan again
            </button>
        </form>
    </div>
</header>
