@extends('layouts.app')

@section('page-title', 'Edit Domain')

@section('content')
<div class="max-w-2xl mx-auto">
    <!-- Header -->
    <div class="mb-8">
        <div class="flex items-center space-x-3">
            <a href="{{ route('dashboard.domains') }}" 
               class="text-gray-400 hover:text-gray-600">
                <i data-lucide="arrow-left" class="w-5 h-5"></i>
            </a>
            <div>
                <h1 class="text-2xl font-bold text-gray-900">Edit Domain</h1>
                <p class="text-gray-600 mt-1">Update domain configuration for {{ $domain->domain }}</p>
            </div>
        </div>
    </div>

    <!-- Form -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <form method="POST" action="{{ route('dashboard.domains.update', $domain) }}" class="space-y-6">
            @csrf
            @method('PUT')
            
            <!-- Domain Name -->
            <div>
                <label for="domain" class="block text-sm font-medium text-gray-700 mb-2">
                    Domain Name <span class="text-red-500">*</span>
                </label>
                <div class="relative">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <i data-lucide="globe" class="h-5 w-5 text-gray-400"></i>
                    </div>
                    <input type="text" 
                           name="domain" 
                           id="domain"
                           value="{{ old('domain', $domain->domain) }}"
                           class="block w-full pl-10 pr-3 py-2 border @error('domain') border-red-300 @else border-gray-300 @enderror rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                           placeholder="example.com"
                           required>
                </div>
                @error('domain')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
                <p class="mt-1 text-sm text-gray-500">
                    Enter the domain name without protocol (e.g., example.com, not https://example.com)
                </p>
            </div>

            <!-- Environment -->
            <div>
                <label for="environment" class="block text-sm font-medium text-gray-700 mb-2">
                    Environment <span class="text-red-500">*</span>
                </label>
                <select name="environment" 
                        id="environment"
                        class="block w-full px-3 py-2 border @error('environment') border-red-300 @else border-gray-300 @enderror rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                        required>
                    <option value="">Select environment</option>
                    <option value="prod" {{ old('environment', $domain->environment) === 'prod' ? 'selected' : '' }}>
                        Production
                    </option>
                    <option value="dev" {{ old('environment', $domain->environment) === 'dev' ? 'selected' : '' }}>
                        Development
                    </option>
                </select>
                @error('environment')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
                <p class="mt-1 text-sm text-gray-500">
                    Production domains are used for live email traffic, Development domains are for testing
                </p>
            </div>

            <!-- Expiry Dates -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <!-- Domain Expiry Date -->
                <div>
                    <label for="domain_expires_at" class="block text-sm font-medium text-gray-700 mb-2">
                        Domain Expiry Date
                    </label>
                    <input type="date" 
                           name="domain_expires_at" 
                           id="domain_expires_at"
                           value="{{ old('domain_expires_at', $domain->domain_expires_at ? $domain->domain_expires_at->format('Y-m-d') : '') }}"
                           class="block w-full px-3 py-2 border @error('domain_expires_at') border-red-300 @else border-gray-300 @enderror rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                    @error('domain_expires_at')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                    <p class="mt-1 text-sm text-gray-500">
                        When your domain registration expires
                    </p>
                    @if($domain->domain_expiry_source)
                        <p class="mt-1 text-xs text-gray-400">
                            Auto-detected on {{ $domain->domain_expiry_detected_at?->format('M d, Y') ?? 'Unknown' }} from {{ $domain->domain_expiry_source }}
                        </p>
                    @endif
                </div>

                <!-- SSL Expiry Date -->
                <div>
                    <label for="ssl_expires_at" class="block text-sm font-medium text-gray-700 mb-2">
                        SSL Certificate Expiry
                    </label>
                    <input type="date" 
                           name="ssl_expires_at" 
                           id="ssl_expires_at"
                           value="{{ old('ssl_expires_at', $domain->ssl_expires_at ? $domain->ssl_expires_at->format('Y-m-d') : '') }}"
                           class="block w-full px-3 py-2 border @error('ssl_expires_at') border-red-300 @else border-gray-300 @enderror rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                    @error('ssl_expires_at')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                    <p class="mt-1 text-sm text-gray-500">
                        When your SSL certificate expires
                    </p>
                    @if($domain->ssl_expiry_source)
                        <p class="mt-1 text-xs text-gray-400">
                            Auto-detected on {{ $domain->ssl_expiry_detected_at?->format('M d, Y') ?? 'Unknown' }} from {{ $domain->ssl_expiry_source }}
                        </p>
                    @endif
                </div>
            </div>

            <!-- Domain Info -->
            <div class="bg-gray-50 border border-gray-200 rounded-md p-4">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <i data-lucide="info" class="h-5 w-5 text-gray-400"></i>
                    </div>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-gray-800">Domain Information</h3>
                        <div class="mt-2 text-sm text-gray-600 space-y-1">
                            <p><strong>Provider:</strong> {{ $domain->provider_guess }}</p>
                            <p><strong>Status:</strong> {{ ucfirst($domain->status) }}</p>
                            <p><strong>Added:</strong> {{ $domain->created_at->format('M j, Y \a\t g:i A') }}</p>
                            @if($domain->last_scanned_at)
                                <p><strong>Last Scan:</strong> {{ $domain->last_scanned_at->diffForHumans() }}</p>
                            @endif
                            @if($domain->score_last)
                                <p><strong>Last Score:</strong> {{ $domain->score_last }}/100</p>
                            @endif
                        </div>
                    </div>
                </div>
            </div>

            <!-- Warning Box -->
            @if($domain->status === 'active' || $domain->score_last)
                <div class="bg-yellow-50 border border-yellow-200 rounded-md p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i data-lucide="alert-triangle" class="h-5 w-5 text-yellow-400"></i>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-medium text-yellow-800">Important Notice</h3>
                            <div class="mt-2 text-sm text-yellow-700">
                                <p>Changing the domain name will reset all scan history and scores. The provider will be automatically re-detected.</p>
                            </div>
                        </div>
                    </div>
                </div>
            @endif

            <!-- Form Actions -->
            <div class="flex items-center justify-end space-x-3 pt-6 border-t border-gray-200">
                <a href="{{ route('dashboard.domains') }}" 
                   class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    Cancel
                </a>
                <button type="submit" 
                        class="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <i data-lucide="save" class="w-4 h-4 inline mr-2"></i>
                    Update Domain
                </button>
            </div>
        </form>
    </div>

    <!-- Danger Zone -->
    <div class="mt-6 bg-white rounded-lg shadow-sm border border-red-200">
        <div class="px-6 py-4 border-b border-red-200">
            <h3 class="text-lg font-medium text-red-900">Danger Zone</h3>
        </div>
        <div class="px-6 py-4">
            <div class="flex items-start justify-between">
                <div>
                    <h4 class="text-sm font-medium text-gray-900">Delete this domain</h4>
                    <p class="text-sm text-gray-600 mt-1">
                        Once you delete a domain, there is no going back. All scan history and data will be permanently removed.
                    </p>
                </div>
                <button onclick="showDeleteModal('{{ $domain->domain }}', {{ $domain->id }})" 
                        class="ml-4 px-4 py-2 text-sm font-medium text-red-700 bg-red-100 border border-red-300 rounded-md hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    <i data-lucide="trash-2" class="w-4 h-4 inline mr-2"></i>
                    Delete Domain
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Delete Confirmation Modal -->
<div id="deleteModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <div class="px-6 py-4">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="alert-triangle" class="h-6 w-6 text-red-600"></i>
                    </div>
                    <div class="ml-3">
                        <h3 class="text-lg font-medium text-gray-900">Delete Domain</h3>
                        <p class="mt-2 text-sm text-gray-500">
                            Are you sure you want to delete <strong id="deleteDomainName"></strong>? 
                            This action cannot be undone and will remove all associated scan data.
                        </p>
                    </div>
                </div>
            </div>
            <div class="px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
                <button onclick="hideDeleteModal()" 
                        class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md">
                    Cancel
                </button>
                <form id="deleteForm" method="POST" class="inline">
                    @csrf
                    @method('DELETE')
                    <button type="submit" 
                            class="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-md">
                        Delete Domain
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
    // Initialize Lucide icons
    lucide.createIcons();
    
    // Auto-format domain input
    document.getElementById('domain').addEventListener('input', function(e) {
        let value = e.target.value.toLowerCase();
        // Remove protocol if entered
        value = value.replace(/^https?:\/\//, '');
        // Remove www if entered
        value = value.replace(/^www\./, '');
        // Remove trailing slash
        value = value.replace(/\/$/, '');
        e.target.value = value;
    });

    function showDeleteModal(domain, domainId) {
        document.getElementById('deleteDomainName').textContent = domain;
        document.getElementById('deleteForm').action = `/dashboard/domains/${domainId}`;
        document.getElementById('deleteModal').classList.remove('hidden');
    }

    function hideDeleteModal() {
        document.getElementById('deleteModal').classList.add('hidden');
    }
</script>
@endsection
