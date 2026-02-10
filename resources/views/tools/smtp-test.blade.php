@extends('layouts.app')

@section('page-title', 'SMTP Test')

@section('content')
<div class="space-y-6">
    <div class="flex items-center space-x-3">
        <a href="{{ route('tools.index') }}" class="text-gray-400 hover:text-gray-600">
            <i data-lucide="arrow-left" class="w-5 h-5"></i>
        </a>
        <div>
            <h1 class="text-2xl font-bold text-gray-900">SMTP Connectivity Test</h1>
            <p class="text-gray-600 mt-1">Test SMTP connectivity, banner response, and STARTTLS support for your mail servers</p>
        </div>
    </div>

    <!-- Input Form -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <form method="POST" action="{{ route('tools.smtp.run') }}">
            @csrf
            <div class="flex flex-col sm:flex-row gap-4">
                <div class="flex-1">
                    <label for="domain" class="block text-sm font-medium text-gray-700 mb-1">Domain</label>
                    <input type="text" name="domain" id="domain" value="{{ $domain ?? old('domain') }}" 
                           placeholder="example.com" required
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    @error('domain') <p class="mt-1 text-sm text-red-600">{{ $message }}</p> @enderror
                </div>
                <div class="w-full sm:w-32">
                    <label for="port" class="block text-sm font-medium text-gray-700 mb-1">Port</label>
                    <select name="port" id="port" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                        <option value="25" {{ ($port ?? 25) == 25 ? 'selected' : '' }}>25</option>
                        <option value="465" {{ ($port ?? 25) == 465 ? 'selected' : '' }}>465</option>
                        <option value="587" {{ ($port ?? 25) == 587 ? 'selected' : '' }}>587</option>
                    </select>
                </div>
                <div class="flex items-end">
                    <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg flex items-center space-x-2 transition-colors">
                        <i data-lucide="wifi" class="w-4 h-4"></i>
                        <span>Test</span>
                    </button>
                </div>
            </div>
        </form>
    </div>

    @if(isset($results))
        <!-- Results -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                <h2 class="text-lg font-semibold text-gray-900">Results for {{ $results['domain'] }} (port {{ $results['port'] }})</h2>
                <p class="text-sm text-gray-500">MX hosts found: {{ count($results['mx_hosts']) }}</p>
            </div>

            <div class="divide-y divide-gray-200">
                @forelse($results['results'] as $host)
                    <div class="p-6">
                        <div class="flex items-center justify-between mb-4">
                            <div class="flex items-center space-x-3">
                                @if($host['connectable'])
                                    <span class="flex-shrink-0 w-8 h-8 rounded-full bg-green-100 flex items-center justify-center">
                                        <i data-lucide="check" class="w-4 h-4 text-green-600"></i>
                                    </span>
                                @else
                                    <span class="flex-shrink-0 w-8 h-8 rounded-full bg-red-100 flex items-center justify-center">
                                        <i data-lucide="x" class="w-4 h-4 text-red-600"></i>
                                    </span>
                                @endif
                                <div>
                                    <h3 class="font-semibold text-gray-900">{{ $host['host'] }}</h3>
                                    <p class="text-sm text-gray-500">Port {{ $host['port'] }} &middot; {{ $host['response_time_ms'] }}ms</p>
                                </div>
                            </div>
                            <div class="flex items-center space-x-2">
                                @if($host['starttls'])
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                        <i data-lucide="lock" class="w-3 h-3 mr-1"></i> STARTTLS
                                    </span>
                                @else
                                    @if($host['connectable'])
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800">
                                            <i data-lucide="lock-open" class="w-3 h-3 mr-1"></i> No STARTTLS
                                        </span>
                                    @endif
                                @endif
                            </div>
                        </div>

                        @if($host['error'])
                            <div class="bg-red-50 border border-red-200 rounded-lg p-3 mb-3">
                                <p class="text-sm text-red-700">{{ $host['error'] }}</p>
                            </div>
                        @endif

                        @if($host['banner'])
                            <div class="space-y-2">
                                <div>
                                    <span class="text-xs font-medium text-gray-500 uppercase">Banner</span>
                                    <p class="text-sm font-mono text-gray-800 bg-gray-50 rounded px-3 py-2 mt-1">{{ $host['banner'] }}</p>
                                </div>
                            </div>
                        @endif

                        @if($host['ehlo_response'])
                            <div class="mt-3">
                                <span class="text-xs font-medium text-gray-500 uppercase">EHLO Capabilities</span>
                                <pre class="text-sm font-mono text-gray-800 bg-gray-50 rounded px-3 py-2 mt-1 whitespace-pre-wrap">{{ $host['ehlo_response'] }}</pre>
                            </div>
                        @endif

                        @if($host['tls_version'])
                            <div class="mt-3">
                                <span class="text-xs font-medium text-gray-500 uppercase">TLS</span>
                                <p class="text-sm text-gray-800 mt-1">{{ $host['tls_version'] }}</p>
                            </div>
                        @endif
                    </div>
                @empty
                    <div class="p-6 text-center text-gray-500">No MX hosts found for this domain.</div>
                @endforelse
            </div>
        </div>
    @endif
</div>
@endsection
