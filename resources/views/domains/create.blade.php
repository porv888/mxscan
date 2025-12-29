@extends('layouts.app')

@section('page-title', 'Add Domain')

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
                <h1 class="text-2xl font-bold text-gray-900">Add New Domain</h1>
                <p class="text-gray-600 mt-1">Add a domain to monitor its email security configuration</p>
            </div>
        </div>
    </div>

    <!-- Form -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <form method="POST" action="{{ route('dashboard.domains.store') }}" class="space-y-6">
            @csrf
            
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
                           value="{{ old('domain') }}"
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
                    <option value="prod" {{ old('environment') === 'prod' ? 'selected' : '' }}>
                        Production
                    </option>
                    <option value="dev" {{ old('environment') === 'dev' ? 'selected' : '' }}>
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

            <!-- Services Selection -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-3">
                    Monitoring Services
                </label>
                <div class="space-y-3">
                    <label class="flex items-start">
                        <input type="checkbox" name="service_dns" id="service_dns" value="1" checked
                               class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                        <div class="ml-3">
                            <span class="text-sm font-medium text-gray-900">DNS Security</span>
                            <p class="text-sm text-gray-500">Monitor MX, SPF, DMARC, TLS-RPT, and MTA-STS records</p>
                        </div>
                    </label>
                    <label class="flex items-start">
                        <input type="checkbox" name="service_spf" id="service_spf" value="1" checked
                               class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                        <div class="ml-3">
                            <span class="text-sm font-medium text-gray-900">SPF Analysis</span>
                            <p class="text-sm text-gray-500">Track SPF record changes and DNS lookup counts</p>
                        </div>
                    </label>
                    <label class="flex items-start">
                        <input type="checkbox" name="service_blacklist" id="service_blacklist" value="1" checked
                               class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                        <div class="ml-3">
                            <span class="text-sm font-medium text-gray-900">Blacklist Monitoring</span>
                            <p class="text-sm text-gray-500">Check against 23+ RBL providers</p>
                        </div>
                    </label>
                    <label class="flex items-start">
                        <input type="checkbox" name="service_delivery" id="service_delivery" value="1"
                               class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                        <div class="ml-3">
                            <span class="text-sm font-medium text-gray-900">Delivery Monitoring</span>
                            <p class="text-sm text-gray-500">Track email delivery times and authentication results</p>
                        </div>
                    </label>
                    <label class="flex items-start">
                        <input type="checkbox" name="service_domain_expiry" id="service_domain_expiry" value="1" checked
                               class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                        <div class="ml-3">
                            <span class="text-sm font-medium text-gray-900">Domain Renewal Monitoring</span>
                            <p class="text-sm text-gray-500">
                                <span class="inline-flex items-center">
                                    <i data-lucide="zap" class="w-3 h-3 mr-1 text-blue-500"></i>
                                    Auto-detected via RDAP/WHOIS
                                </span>
                                • Get alerts at 30, 14, 7, 3, 1 days before expiry
                            </p>
                        </div>
                    </label>
                    <label class="flex items-start">
                        <input type="checkbox" name="service_ssl_expiry" id="service_ssl_expiry" value="1" checked
                               class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                        <div class="ml-3">
                            <span class="text-sm font-medium text-gray-900">SSL Certificate Monitoring</span>
                            <p class="text-sm text-gray-500">
                                <span class="inline-flex items-center">
                                    <i data-lucide="zap" class="w-3 h-3 mr-1 text-blue-500"></i>
                                    Auto-detected daily
                                </span>
                                • Get alerts at 30, 14, 7, 3, 1 days before expiry
                            </p>
                        </div>
                    </label>
                </div>
            </div>

            <!-- Schedule Configuration -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-3">
                    Scan Schedule
                </label>
                <div class="space-y-3">
                    <label class="flex items-center">
                        <input type="radio" name="schedule_type" value="off" checked
                               class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300">
                        <span class="ml-3 text-sm text-gray-900">Manual only (no automatic scans)</span>
                    </label>
                    <label class="flex items-center">
                        <input type="radio" name="schedule_type" value="daily"
                               class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300">
                        <span class="ml-3 text-sm text-gray-900">Daily</span>
                    </label>
                    <label class="flex items-center">
                        <input type="radio" name="schedule_type" value="weekly"
                               class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300">
                        <span class="ml-3 text-sm text-gray-900">Weekly</span>
                    </label>
                </div>
                <div id="time-picker" class="mt-3 hidden">
                    <label for="schedule_time" class="block text-sm text-gray-700 mb-1">Run at (UTC):</label>
                    <input type="time" id="schedule_time" value="09:00"
                           class="block w-40 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                </div>
            </div>


            <!-- Hidden fields for form submission -->
            <input type="hidden" name="services[]" id="hidden_services" value="">
            <input type="hidden" name="schedule" id="hidden_schedule" value="off">

            <!-- Info Box -->
            <div class="bg-blue-50 border border-blue-200 rounded-md p-4">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <i data-lucide="info" class="h-5 w-5 text-blue-400"></i>
                    </div>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-blue-800">What happens next?</h3>
                        <div class="mt-2 text-sm text-blue-700">
                            <ul class="list-disc pl-5 space-y-1">
                                <li>We'll automatically detect your email provider</li>
                                <li>The domain will be added to your monitoring dashboard</li>
                                <li>You can run security scans to check SPF, DKIM, and DMARC records</li>
                                <li>Get recommendations to improve your email security</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Form Actions -->
            <div class="flex items-center justify-end space-x-3 pt-6 border-t border-gray-200">
                <a href="{{ route('dashboard.domains') }}" 
                   class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    Cancel
                </a>
                <button type="submit" 
                        class="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <i data-lucide="plus" class="w-4 h-4 inline mr-2"></i>
                    Add Domain
                </button>
            </div>
        </form>
    </div>

    <!-- Additional Help -->
    <div class="mt-6 bg-gray-50 rounded-lg p-4">
        <h3 class="text-sm font-medium text-gray-900 mb-2">Need help?</h3>
        <div class="text-sm text-gray-600 space-y-1">
            <p>• Make sure you own or manage the domain you're adding</p>
            <p>• You can add subdomains (e.g., app.example.com) if you already have the parent domain</p>
            <p>• You can add multiple domains to monitor different email configurations</p>
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

    // Handle schedule type changes
    const scheduleRadios = document.querySelectorAll('input[name="schedule_type"]');
    const timePicker = document.getElementById('time-picker');
    
    scheduleRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.value === 'off') {
                timePicker.classList.add('hidden');
            } else {
                timePicker.classList.remove('hidden');
            }
            updateHiddenFields();
        });
    });

    // Update hidden fields before form submission
    function updateHiddenFields() {
        // Collect selected services
        const services = [];
        if (document.getElementById('service_dns').checked) services.push('dns');
        if (document.getElementById('service_spf').checked) services.push('spf');
        if (document.getElementById('service_blacklist').checked) services.push('blacklist');
        if (document.getElementById('service_delivery').checked) services.push('delivery');
        if (document.getElementById('service_domain_expiry').checked) services.push('domain_expiry');
        if (document.getElementById('service_ssl_expiry').checked) services.push('ssl_expiry');
        
        // Clear existing hidden service inputs
        const existingInputs = document.querySelectorAll('input[name="services[]"]');
        existingInputs.forEach(input => input.remove());
        
        // Create new hidden inputs for each service
        const form = document.querySelector('form');
        services.forEach(service => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'services[]';
            input.value = service;
            form.appendChild(input);
        });
        
        // Update schedule hidden field
        const scheduleType = document.querySelector('input[name="schedule_type"]:checked').value;
        let scheduleValue = scheduleType;
        
        if (scheduleType !== 'off') {
            const time = document.getElementById('schedule_time').value;
            scheduleValue = scheduleType + '@' + time;
        }
        
        document.getElementById('hidden_schedule').value = scheduleValue;
    }

    // Update hidden fields on checkbox changes
    document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
        checkbox.addEventListener('change', updateHiddenFields);
    });

    // Update hidden fields on time change
    document.getElementById('schedule_time').addEventListener('change', updateHiddenFields);

    // Update hidden fields before form submission
    document.querySelector('form').addEventListener('submit', function(e) {
        updateHiddenFields();
    });

    // Initialize on page load
    updateHiddenFields();
</script>
@endsection
