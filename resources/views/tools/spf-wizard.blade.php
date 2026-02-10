@extends('layouts.app')

@section('page-title', 'SPF Wizard')

@section('content')
<div class="space-y-6">
    <div class="flex items-center space-x-3">
        <a href="{{ route('tools.index') }}" class="text-gray-400 hover:text-gray-600">
            <i data-lucide="arrow-left" class="w-5 h-5"></i>
        </a>
        <div>
            <h1 class="text-2xl font-bold text-gray-900">SPF Record Wizard</h1>
            <p class="text-gray-600 mt-1">Build an SPF record by selecting your email providers and adding custom entries</p>
        </div>
    </div>

    <form method="POST" action="{{ route('tools.spf.run') }}">
        @csrf
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Left: Configuration -->
            <div class="lg:col-span-2 space-y-6">
                <!-- Domain -->
                <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                    <h2 class="text-base font-semibold text-gray-900 mb-4">Domain</h2>
                    <input type="text" name="domain" value="{{ $domain ?? old('domain') }}"
                           placeholder="example.com" required
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500">
                    @error('domain') <p class="mt-1 text-sm text-red-600">{{ $message }}</p> @enderror
                </div>

                <!-- Email Providers -->
                <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                    <h2 class="text-base font-semibold text-gray-900 mb-4">Email Providers</h2>
                    <p class="text-sm text-gray-500 mb-4">Select the services that send email on behalf of your domain</p>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        @foreach($providers as $key => $provider)
                            <label class="flex items-center space-x-3 p-3 rounded-lg border border-gray-200 hover:bg-gray-50 cursor-pointer transition-colors">
                                <input type="checkbox" name="providers[]" value="{{ $key }}"
                                       {{ in_array($key, $selectedProviders ?? []) ? 'checked' : '' }}
                                       class="h-4 w-4 text-amber-600 border-gray-300 rounded focus:ring-amber-500">
                                <span class="text-sm font-medium text-gray-700">{{ $provider['name'] }}</span>
                            </label>
                        @endforeach
                    </div>
                </div>

                <!-- Additional Options -->
                <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                    <h2 class="text-base font-semibold text-gray-900 mb-4">Additional Options</h2>

                    <div class="space-y-4">
                        <!-- Use MX -->
                        <label class="flex items-center space-x-3">
                            <input type="checkbox" name="use_mx" value="1"
                                   {{ ($useMx ?? false) ? 'checked' : '' }}
                                   class="h-4 w-4 text-amber-600 border-gray-300 rounded focus:ring-amber-500">
                            <div>
                                <span class="text-sm font-medium text-gray-700">Include MX servers</span>
                                <p class="text-xs text-gray-500">Allow your MX mail servers to send email (adds <code>mx</code> mechanism)</p>
                            </div>
                        </label>

                        <!-- Custom IPs -->
                        <div>
                            <label for="custom_ips" class="block text-sm font-medium text-gray-700 mb-1">Custom IP Addresses</label>
                            <input type="text" name="custom_ips" id="custom_ips" value="{{ $customIps ?? old('custom_ips') }}"
                                   placeholder="203.0.113.5, 198.51.100.0/24"
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500">
                            <p class="mt-1 text-xs text-gray-500">Comma or space separated. IPv4 and IPv6 supported, CIDR notation allowed.</p>
                        </div>

                        <!-- Custom Includes -->
                        <div>
                            <label for="custom_includes" class="block text-sm font-medium text-gray-700 mb-1">Custom Includes</label>
                            <input type="text" name="custom_includes" id="custom_includes" value="{{ $customIncludes ?? old('custom_includes') }}"
                                   placeholder="_spf.example.com, other.provider.com"
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500">
                            <p class="mt-1 text-xs text-gray-500">Additional include: domains, comma or space separated.</p>
                        </div>

                        <!-- Qualifier -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Policy (All Qualifier)</label>
                            <div class="space-y-2">
                                <label class="flex items-center space-x-3">
                                    <input type="radio" name="qualifier" value="-all"
                                           {{ ($qualifier ?? '~all') === '-all' ? 'checked' : '' }}
                                           class="h-4 w-4 text-amber-600 border-gray-300 focus:ring-amber-500">
                                    <div>
                                        <span class="text-sm font-medium text-gray-700">-all (Fail)</span>
                                        <span class="text-xs text-gray-500 ml-1">Strict &mdash; reject unauthorized senders</span>
                                    </div>
                                </label>
                                <label class="flex items-center space-x-3">
                                    <input type="radio" name="qualifier" value="~all"
                                           {{ ($qualifier ?? '~all') === '~all' ? 'checked' : '' }}
                                           class="h-4 w-4 text-amber-600 border-gray-300 focus:ring-amber-500">
                                    <div>
                                        <span class="text-sm font-medium text-gray-700">~all (SoftFail)</span>
                                        <span class="text-xs text-gray-500 ml-1">Recommended &mdash; mark but don't reject</span>
                                    </div>
                                </label>
                                <label class="flex items-center space-x-3">
                                    <input type="radio" name="qualifier" value="?all"
                                           {{ ($qualifier ?? '~all') === '?all' ? 'checked' : '' }}
                                           class="h-4 w-4 text-amber-600 border-gray-300 focus:ring-amber-500">
                                    <div>
                                        <span class="text-sm font-medium text-gray-700">?all (Neutral)</span>
                                        <span class="text-xs text-gray-500 ml-1">Permissive &mdash; no policy enforced</span>
                                    </div>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>

                <button type="submit" class="w-full bg-amber-600 hover:bg-amber-700 text-white px-6 py-3 rounded-lg flex items-center justify-center space-x-2 transition-colors font-medium">
                    <i data-lucide="wand-2" class="w-5 h-5"></i>
                    <span>Generate SPF Record</span>
                </button>
            </div>

            <!-- Right: Generated Record -->
            <div class="space-y-6">
                @if(isset($generatedRecord))
                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 sticky top-6">
                        <h2 class="text-base font-semibold text-gray-900 mb-4">Generated SPF Record</h2>

                        <!-- Lookup Count -->
                        <div class="mb-4">
                            <div class="flex items-center justify-between text-sm mb-1">
                                <span class="text-gray-600">DNS Lookups</span>
                                <span class="font-semibold {{ $lookupCount > 10 ? 'text-red-600' : ($lookupCount >= 8 ? 'text-amber-600' : 'text-green-600') }}">
                                    {{ $lookupCount }} / 10
                                </span>
                            </div>
                            <div class="w-full bg-gray-200 rounded-full h-2">
                                <div class="h-2 rounded-full {{ $lookupCount > 10 ? 'bg-red-500' : ($lookupCount >= 8 ? 'bg-amber-500' : 'bg-green-500') }}"
                                     style="width: {{ min(100, ($lookupCount / 10) * 100) }}%"></div>
                            </div>
                            @if($lookupCount > 10)
                                <p class="text-xs text-red-600 mt-1">Exceeds the RFC 7208 limit of 10 DNS lookups. Consider using IP addresses directly or reducing includes.</p>
                            @endif
                        </div>

                        <!-- Record -->
                        <div class="relative" x-data="{ copied: false }">
                            <div class="bg-gray-900 text-green-400 rounded-lg p-4 font-mono text-sm break-all">
                                {{ $generatedRecord }}
                            </div>
                            <button type="button"
                                    @click="navigator.clipboard.writeText('{{ addslashes($generatedRecord) }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                    class="absolute top-2 right-2 p-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white transition-colors">
                                <i data-lucide="copy" class="w-4 h-4" x-show="!copied"></i>
                                <i data-lucide="check" class="w-4 h-4" x-show="copied" x-cloak></i>
                            </button>
                        </div>

                        <!-- DNS Instructions -->
                        <div class="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-3">
                            <h4 class="text-xs font-semibold text-blue-800 uppercase mb-1">How to apply</h4>
                            <ol class="text-xs text-blue-700 space-y-1 list-decimal list-inside">
                                <li>Log in to your DNS provider</li>
                                <li>Add/update a TXT record for <code class="bg-blue-100 px-1 rounded">{{ $domain }}</code></li>
                                <li>Paste the generated record as the value</li>
                                <li>Wait for DNS propagation (up to 48h)</li>
                            </ol>
                        </div>

                        @if($currentSpf)
                            <div class="mt-4">
                                <h3 class="text-sm font-medium text-gray-700 mb-2">Current SPF Record</h3>
                                <div class="bg-gray-50 rounded-lg p-3 font-mono text-xs text-gray-600 break-all">{{ $currentSpf }}</div>
                            </div>
                        @endif
                    </div>
                @else
                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                        <div class="text-center text-gray-400 py-8">
                            <i data-lucide="wand-2" class="w-12 h-12 mx-auto mb-3 opacity-50"></i>
                            <p class="text-sm">Configure your options and click <strong>Generate</strong> to build your SPF record</p>
                        </div>
                    </div>
                @endif
            </div>
        </div>
    </form>
</div>
@endsection
