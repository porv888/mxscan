@extends('layouts.app')

@section('page-title', 'BIMI Check')

@section('content')
<div class="space-y-6">
    <div class="flex items-center space-x-3">
        <a href="{{ route('tools.index') }}" class="text-gray-400 hover:text-gray-600">
            <i data-lucide="arrow-left" class="w-5 h-5"></i>
        </a>
        <div>
            <h1 class="text-2xl font-bold text-gray-900">BIMI Record Check</h1>
            <p class="text-gray-600 mt-1">Validate your BIMI DNS record and SVG logo for inbox brand display</p>
        </div>
    </div>

    <!-- Input Form -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <form method="POST" action="{{ route('tools.bimi.run') }}">
            @csrf
            <div class="flex flex-col sm:flex-row gap-4">
                <div class="flex-1">
                    <label for="domain" class="block text-sm font-medium text-gray-700 mb-1">Domain</label>
                    <input type="text" name="domain" id="domain" value="{{ $domain ?? old('domain') }}"
                           placeholder="example.com" required
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500">
                    @error('domain') <p class="mt-1 text-sm text-red-600">{{ $message }}</p> @enderror
                </div>
                <div class="flex items-end">
                    <button type="submit" class="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-lg flex items-center space-x-2 transition-colors">
                        <i data-lucide="image" class="w-4 h-4"></i>
                        <span>Check</span>
                    </button>
                </div>
            </div>
        </form>
    </div>

    @if(isset($results))
        <!-- Results -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                <div class="flex items-center space-x-3">
                    @if($results['record_found'])
                        <span class="flex-shrink-0 w-8 h-8 rounded-full bg-green-100 flex items-center justify-center">
                            <i data-lucide="check" class="w-4 h-4 text-green-600"></i>
                        </span>
                        <h2 class="text-lg font-semibold text-gray-900">BIMI Record Found</h2>
                    @else
                        <span class="flex-shrink-0 w-8 h-8 rounded-full bg-red-100 flex items-center justify-center">
                            <i data-lucide="x" class="w-4 h-4 text-red-600"></i>
                        </span>
                        <h2 class="text-lg font-semibold text-gray-900">No BIMI Record Found</h2>
                    @endif
                </div>
            </div>

            <div class="p-6 space-y-4">
                <!-- DNS Record -->
                <div>
                    <span class="text-xs font-medium text-gray-500 uppercase">DNS Lookup</span>
                    <p class="text-sm font-mono text-gray-600 mt-1">default._bimi.{{ $results['domain'] }}</p>
                </div>

                @if($results['raw_record'])
                    <div>
                        <span class="text-xs font-medium text-gray-500 uppercase">Raw Record</span>
                        <p class="text-sm font-mono text-gray-800 bg-gray-50 rounded px-3 py-2 mt-1 break-all">{{ $results['raw_record'] }}</p>
                    </div>
                @endif

                @if($results['logo_url'])
                    <div>
                        <span class="text-xs font-medium text-gray-500 uppercase">Logo URL</span>
                        <p class="text-sm mt-1">
                            <a href="{{ $results['logo_url'] }}" target="_blank" class="text-blue-600 hover:underline break-all">{{ $results['logo_url'] }}</a>
                        </p>
                    </div>
                @endif

                @if($results['authority_url'])
                    <div>
                        <span class="text-xs font-medium text-gray-500 uppercase">Authority (VMC) URL</span>
                        <p class="text-sm mt-1">
                            <a href="{{ $results['authority_url'] }}" target="_blank" class="text-blue-600 hover:underline break-all">{{ $results['authority_url'] }}</a>
                        </p>
                    </div>
                @endif

                <!-- Validation Status -->
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4 border-t border-gray-200">
                    <div class="flex items-center space-x-2">
                        @if($results['record_found'])
                            <i data-lucide="check-circle" class="w-5 h-5 text-green-500"></i>
                            <span class="text-sm text-gray-700">DNS Record</span>
                        @else
                            <i data-lucide="x-circle" class="w-5 h-5 text-red-500"></i>
                            <span class="text-sm text-gray-700">DNS Record</span>
                        @endif
                    </div>
                    <div class="flex items-center space-x-2">
                        @if($results['logo_url'])
                            <i data-lucide="check-circle" class="w-5 h-5 text-green-500"></i>
                            <span class="text-sm text-gray-700">Logo Tag</span>
                        @else
                            <i data-lucide="x-circle" class="w-5 h-5 text-red-500"></i>
                            <span class="text-sm text-gray-700">Logo Tag</span>
                        @endif
                    </div>
                    <div class="flex items-center space-x-2">
                        @if($results['logo_valid'])
                            <i data-lucide="check-circle" class="w-5 h-5 text-green-500"></i>
                            <span class="text-sm text-gray-700">SVG Valid</span>
                        @else
                            <i data-lucide="x-circle" class="w-5 h-5 text-red-500"></i>
                            <span class="text-sm text-gray-700">SVG Valid</span>
                        @endif
                    </div>
                </div>

                @if($results['logo_content_type'] || $results['logo_size_bytes'])
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                        @if($results['logo_content_type'])
                            <div>
                                <span class="text-xs font-medium text-gray-500 uppercase">Content-Type</span>
                                <p class="text-sm text-gray-800 mt-1">{{ $results['logo_content_type'] }}</p>
                            </div>
                        @endif
                        @if($results['logo_size_bytes'])
                            <div>
                                <span class="text-xs font-medium text-gray-500 uppercase">File Size</span>
                                <p class="text-sm text-gray-800 mt-1">{{ number_format($results['logo_size_bytes']) }} bytes</p>
                            </div>
                        @endif
                    </div>
                @endif

                @if(!empty($results['logo_errors']))
                    <div class="bg-red-50 border border-red-200 rounded-lg p-4 mt-4">
                        <h4 class="text-sm font-semibold text-red-800 mb-2">Issues Found</h4>
                        <ul class="space-y-1">
                            @foreach($results['logo_errors'] as $error)
                                <li class="text-sm text-red-700 flex items-start space-x-2">
                                    <i data-lucide="alert-circle" class="w-4 h-4 mt-0.5 flex-shrink-0"></i>
                                    <span>{{ $error }}</span>
                                </li>
                            @endforeach
                        </ul>
                    </div>
                @endif

                @if(!$results['record_found'])
                    <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mt-4">
                        <h4 class="text-sm font-semibold text-blue-800 mb-2">How to set up BIMI</h4>
                        <ol class="space-y-1 text-sm text-blue-700 list-decimal list-inside">
                            <li>Create an SVG Tiny PS logo file (square format recommended)</li>
                            <li>Host the SVG on HTTPS (e.g., https://example.com/logo.svg)</li>
                            <li>Add a TXT record at <code class="bg-blue-100 px-1 rounded">default._bimi.{{ $results['domain'] }}</code></li>
                            <li>Set the value to: <code class="bg-blue-100 px-1 rounded">v=BIMI1; l=https://example.com/logo.svg;</code></li>
                            <li>Optional: Get a VMC certificate for verified display in Gmail</li>
                        </ol>
                    </div>
                @endif
            </div>
        </div>
    @endif
</div>
@endsection
