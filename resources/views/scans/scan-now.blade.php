@extends('layouts.app')

@section('content')
<div class="mx-auto max-w-lg px-6 py-10">
    <div class="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
        <h1 class="text-2xl font-semibold text-gray-900">Run scan</h1>
        <p class="mt-2 text-sm leading-6 text-gray-600">
            Start a new scan for <span class="font-medium text-gray-900">{{ $domain->domain }}</span>.
        </p>

        @php
            $modeLabel = match ($mode) {
                'dns' => 'DNS only',
                'spf' => 'SPF only',
                'blacklist' => 'Blacklist only',
                default => 'Full scan',
            };
        @endphp

        <p class="mt-3 text-sm text-gray-500">Scan type: {{ $modeLabel }}</p>

        <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="mt-6">
            @csrf
            <input type="hidden" name="mode" value="{{ $mode }}">
            <div class="flex flex-wrap gap-3">
                <button type="submit" class="mx-btn mx-btn-primary">
                    <i data-lucide="scan" class="h-4 w-4"></i>
                    Start scan
                </button>
                <a href="{{ route('dashboard.domains') }}" class="mx-btn mx-btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>
@endsection
