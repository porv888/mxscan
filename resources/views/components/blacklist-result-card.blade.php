@props(['results', 'summary'])

<div class="bg-white rounded-lg border border-gray-200 p-6">
    <div class="flex items-center justify-between mb-6">
        <h3 class="text-lg font-semibold text-gray-900">Blacklist Status</h3>
        @if($summary)
            <x-blacklist-status-badge 
                :status="$summary['is_clean'] ? 'clean' : 'listed'" 
                :count="$summary['listed_count'] ?? 0"
                size="lg" />
        @endif
    </div>

    @if($summary)
        <!-- Improved Summary Block -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-gray-100 p-4 rounded-lg text-center">
                <div class="text-2xl font-bold text-gray-900">{{ $summary['unique_ips'] ?? 0 }}</div>
                <div class="text-sm text-gray-600">IPs Checked</div>
            </div>
            <div class="bg-gray-100 p-4 rounded-lg text-center">
                <div class="text-2xl font-bold text-gray-900">{{ $summary['providers_checked'] ?? 0 }}</div>
                <div class="text-sm text-gray-600">RBL Providers</div>
            </div>
            <div class="bg-green-100 p-4 rounded-lg text-center">
                <div class="text-2xl font-bold text-green-700">{{ $summary['ok_count'] ?? 0 }}</div>
                <div class="text-sm text-green-600">✔ Clean</div>
            </div>
            <div class="bg-red-100 p-4 rounded-lg text-center">
                <div class="text-2xl font-bold text-red-700">{{ $summary['listed_count'] ?? 0 }}</div>
                <div class="text-sm text-red-600">❌ Listed</div>
            </div>
        </div>

        @if($results && $results->count() > 0)
            <!-- Results Grouped by IP -->
            <div class="space-y-4">
                @foreach($results->groupBy('ip_address') as $ip => $ipResults)
                    @php
                        $listedResults = $ipResults->where('status', 'listed');
                        $cleanResults = $ipResults->where('status', 'ok');
                        $isListed = $listedResults->count() > 0;
                    @endphp
                    
                    <div class="border rounded-lg shadow-sm overflow-hidden">
                        <!-- IP Header -->
                        <div class="flex justify-between items-center p-4 {{ $isListed ? 'bg-red-50 border-b border-red-200' : 'bg-green-50 border-b border-green-200' }}">
                            <div class="flex items-center space-x-3">
                                <i data-lucide="server" class="w-5 h-5 text-gray-500"></i>
                                <span class="font-medium text-gray-900">{{ $ip }}</span>
                                <button onclick="copyToClipboard('{{ $ip }}', this)" 
                                        class="text-xs px-2 py-1 bg-white hover:bg-gray-50 border border-gray-300 rounded text-gray-600">
                                    Copy IP
                                </button>
                            </div>
                            <div class="flex items-center space-x-2">
                                @if($isListed)
                                    <span class="px-3 py-1 text-sm bg-red-200 text-red-800 rounded-full font-medium">
                                        ❌ Listed ({{ $listedResults->count() }})
                                    </span>
                                @else
                                    <span class="px-3 py-1 text-sm bg-green-200 text-green-800 rounded-full font-medium">
                                        🟢 Clean
                                    </span>
                                @endif
                                @if($cleanResults->count() > 0 && $isListed)
                                    <button onclick="toggleCleanResults('{{ $ip }}')" 
                                            class="text-xs px-2 py-1 bg-gray-200 hover:bg-gray-300 rounded text-gray-600">
                                        Show {{ $cleanResults->count() }} Clean
                                    </button>
                                @endif
                            </div>
                        </div>

                        <!-- Results Content -->
                        <div class="divide-y divide-gray-200">
                            @if($isListed)
                                <!-- Listed Results (Always Visible) -->
                                @foreach($listedResults as $result)
                                    <div class="flex justify-between items-center p-4 bg-red-50">
                                        <div class="flex items-center space-x-3">
                                            <span class="text-red-600">❌</span>
                                            <div>
                                                <span class="font-medium text-red-800">{{ $result->provider }}</span>
                                                @if($result->message)
                                                    <p class="text-sm text-red-600 mt-1">{{ $result->message }}</p>
                                                @endif
                                            </div>
                                        </div>
                                        @if($result->removal_url)
                                            <a href="{{ $result->removal_url }}" 
                                               target="_blank" 
                                               class="inline-flex items-center px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg font-medium">
                                                <i data-lucide="external-link" class="w-4 h-4 mr-2"></i>
                                                Request Delisting
                                            </a>
                                        @endif
                                    </div>
                                @endforeach

                                <!-- Clean Results (Collapsible) -->
                                <div id="clean-results-{{ Str::slug($ip) }}" class="hidden">
                                    @foreach($cleanResults as $result)
                                        <div class="flex justify-between items-center p-3 bg-green-50">
                                            <div class="flex items-center space-x-3">
                                                <span class="text-green-600">✅</span>
                                                <span class="text-green-800">{{ $result->provider }}</span>
                                            </div>
                                            <span class="text-green-600 text-sm">Clean</span>
                                        </div>
                                    @endforeach
                                </div>
                            @else
                                <!-- All Clean - Show Summary -->
                                <div class="p-4 bg-green-50">
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center space-x-3">
                                            <span class="text-green-600">✅</span>
                                            <span class="text-green-800 font-medium">All {{ $cleanResults->count() }} RBL providers report clean</span>
                                        </div>
                                        <button onclick="toggleCleanResults('{{ $ip }}')" 
                                                class="text-xs px-2 py-1 bg-green-200 hover:bg-green-300 rounded text-green-700">
                                            Show Details
                                        </button>
                                    </div>
                                    
                                    <!-- Detailed Clean Results (Collapsible) -->
                                    <div id="clean-results-{{ Str::slug($ip) }}" class="hidden mt-3 space-y-2">
                                        @foreach($cleanResults as $result)
                                            <div class="flex items-center justify-between p-2 bg-white rounded border border-green-200">
                                                <span class="text-green-800 text-sm">{{ $result->provider }}</span>
                                                <span class="text-green-600 text-xs">✅ Clean</span>
                                            </div>
                                        @endforeach
                                    </div>
                                </div>
                            @endif
                        </div>
                    </div>
                @endforeach
            </div>

            @if($summary['listed_count'] > 0)
                <!-- Action Summary for Listed IPs -->
                <div class="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                    <div class="flex items-start">
                        <i data-lucide="alert-triangle" class="w-5 h-5 text-yellow-600 mt-0.5 mr-3 flex-shrink-0"></i>
                        <div>
                            <h4 class="font-medium text-yellow-800">Action Required</h4>
                            <p class="text-sm text-yellow-700 mt-1">
                                {{ $summary['listed_count'] }} blacklist{{ $summary['listed_count'] > 1 ? 's' : '' }} found. 
                                Click "Request Delisting" buttons above to remove your IPs from these blacklists.
                            </p>
                        </div>
                    </div>
                </div>
            @endif
        @endif
    @else
        <!-- No Results State -->
        <div class="text-center py-8">
            <div class="mx-auto h-12 w-12 text-gray-400 mb-4">
                <i data-lucide="shield-check" class="h-12 w-12"></i>
            </div>
            <h4 class="text-lg font-medium text-gray-900 mb-2">No Blacklist Check Yet</h4>
            <p class="text-gray-600 mb-4">Run a blacklist check to see if your domain's IPs are listed on spam blacklists.</p>
            <button onclick="runBlacklistCheck()" 
                    class="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg">
                <i data-lucide="shield-check" class="w-4 h-4 mr-2"></i>
                Run Blacklist Check
            </button>
        </div>
    @endif
</div>

<script>
function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.innerText;
        const originalClasses = button.className;
        button.innerText = 'Copied!';
        button.className = button.className.replace('bg-white', 'bg-green-100').replace('text-gray-600', 'text-green-700');
        setTimeout(() => {
            button.innerText = originalText;
            button.className = originalClasses;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

function toggleCleanResults(ip) {
    const slug = ip.replace(/[^a-zA-Z0-9]/g, '-').toLowerCase();
    const element = document.getElementById(`clean-results-${slug}`);
    const button = event.target;
    
    if (element.classList.contains('hidden')) {
        element.classList.remove('hidden');
        button.innerText = button.innerText.replace('Show', 'Hide');
    } else {
        element.classList.add('hidden');
        button.innerText = button.innerText.replace('Hide', 'Show');
    }
}
</script>