@extends('layouts.app')

@section('page-title', 'DKIM Lookup')

@section('content')
<div class="space-y-6">
    <div class="flex items-center space-x-3">
        <a href="{{ route('tools.index') }}" class="text-gray-400 hover:text-gray-600">
            <i data-lucide="arrow-left" class="w-5 h-5"></i>
        </a>
        <div>
            <h1 class="text-2xl font-bold text-gray-900">DKIM Selector Lookup</h1>
            <p class="text-gray-600 mt-1">Check DKIM public keys published in DNS. Leave selector blank to probe {{ count(config('dkim.selectors', [])) }} common selectors.</p>
        </div>
    </div>

    <!-- Input Form -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <form method="POST" action="{{ route('tools.dkim.run') }}">
            @csrf
            <div class="flex flex-col sm:flex-row gap-4">
                <div class="flex-1">
                    <label for="domain" class="block text-sm font-medium text-gray-700 mb-1">Domain</label>
                    <input type="text" name="domain" id="domain" value="{{ $domain ?? old('domain') }}"
                           placeholder="example.com" required
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                    @error('domain') <p class="mt-1 text-sm text-red-600">{{ $message }}</p> @enderror
                </div>
                <div class="w-full sm:w-48">
                    <label for="selector" class="block text-sm font-medium text-gray-700 mb-1">Selector <span class="text-gray-400">(optional)</span></label>
                    <input type="text" name="selector" id="selector" value="{{ $selectorInput ?? old('selector') }}"
                           placeholder="e.g. google, selector1"
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                </div>
                <div class="flex items-end">
                    <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg flex items-center space-x-2 transition-colors">
                        <i data-lucide="key" class="w-4 h-4"></i>
                        <span>Lookup</span>
                    </button>
                </div>
            </div>
        </form>
    </div>

    @if(isset($results))
        <!-- Results -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                <div class="flex items-center justify-between">
                    <h2 class="text-lg font-semibold text-gray-900">
                        @if(count($results) > 0)
                            {{ count($results) }} DKIM key{{ count($results) > 1 ? 's' : '' }} found for {{ $domain }}
                        @else
                            No DKIM keys found for {{ $domain }}
                        @endif
                    </h2>
                    @if(!empty($selectorInput))
                        <span class="text-sm text-gray-500">Checked selector: <code class="bg-gray-100 px-1 rounded">{{ $selectorInput }}</code></span>
                    @else
                        <span class="text-sm text-gray-500">Probed {{ count(config('dkim.selectors', [])) }} common selectors</span>
                    @endif
                </div>
            </div>

            @if(count($results) > 0)
                <div class="divide-y divide-gray-200">
                    @foreach($results as $dkim)
                        <div class="p-6">
                            <div class="flex items-center justify-between mb-3">
                                <div class="flex items-center space-x-3">
                                    <span class="inline-flex items-center px-2.5 py-1 rounded-md text-sm font-medium bg-purple-100 text-purple-800">
                                        {{ $dkim['selector'] }}
                                    </span>
                                    <span class="text-sm text-gray-500 font-mono">{{ $dkim['dns_name'] }}</span>
                                </div>
                                <div class="flex items-center space-x-2">
                                    @if($dkim['status'] === 'strong')
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            <i data-lucide="shield-check" class="w-3 h-3 mr-1"></i> Strong
                                        </span>
                                    @elseif($dkim['status'] === 'ok')
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                            <i data-lucide="check" class="w-3 h-3 mr-1"></i> OK
                                        </span>
                                    @elseif($dkim['status'] === 'weak')
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                            <i data-lucide="alert-triangle" class="w-3 h-3 mr-1"></i> Weak
                                        </span>
                                    @elseif($dkim['status'] === 'revoked')
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                                            <i data-lucide="x" class="w-3 h-3 mr-1"></i> Revoked
                                        </span>
                                    @else
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                                            Unknown
                                        </span>
                                    @endif
                                </div>
                            </div>

                            <div class="grid grid-cols-2 sm:grid-cols-3 gap-4 mb-3">
                                <div>
                                    <span class="text-xs font-medium text-gray-500 uppercase">Key Type</span>
                                    <p class="text-sm font-medium text-gray-900 mt-0.5">{{ strtoupper($dkim['key_type']) }}</p>
                                </div>
                                <div>
                                    <span class="text-xs font-medium text-gray-500 uppercase">Key Size</span>
                                    <p class="text-sm font-medium text-gray-900 mt-0.5">{{ $dkim['key_bits'] ? $dkim['key_bits'] . ' bits' : 'Unknown' }}</p>
                                </div>
                                <div>
                                    <span class="text-xs font-medium text-gray-500 uppercase">Strength</span>
                                    <p class="text-sm font-medium mt-0.5 {{ $dkim['status'] === 'strong' ? 'text-green-700' : ($dkim['status'] === 'ok' ? 'text-blue-700' : ($dkim['status'] === 'weak' ? 'text-red-700' : 'text-gray-700')) }}">
                                        @if($dkim['key_bits'] && $dkim['key_bits'] >= 2048) 2048+ bit (recommended)
                                        @elseif($dkim['key_bits'] && $dkim['key_bits'] >= 1024) 1024 bit (acceptable)
                                        @elseif($dkim['key_bits'] && $dkim['key_bits'] < 1024) Below 1024 bit (upgrade recommended)
                                        @elseif($dkim['status'] === 'revoked') Key revoked (p= is empty)
                                        @else Could not determine
                                        @endif
                                    </p>
                                </div>
                            </div>

                            <div>
                                <span class="text-xs font-medium text-gray-500 uppercase">Raw Record</span>
                                <pre class="text-xs font-mono text-gray-800 bg-gray-50 rounded-lg px-3 py-2 mt-1 whitespace-pre-wrap break-all">{{ $dkim['record'] }}</pre>
                            </div>
                        </div>
                    @endforeach
                </div>
            @else
                <div class="p-8 text-center">
                    <i data-lucide="key" class="w-12 h-12 mx-auto text-gray-300 mb-3"></i>
                    <p class="text-gray-500 mb-2">No DKIM keys found</p>
                    <p class="text-sm text-gray-400">
                        @if(!empty($selectorInput))
                            The selector <code class="bg-gray-100 px-1 rounded">{{ $selectorInput }}</code> was not found. Try without a selector to probe common ones.
                        @else
                            None of the {{ count(config('dkim.selectors', [])) }} common selectors were found. Your domain may use a custom selector.
                        @endif
                    </p>
                </div>
            @endif
        </div>
    @endif
</div>
@endsection
