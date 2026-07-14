@extends('layouts.app')

@section('page-title', 'Scan your domain')

@section('content')
<div class="max-w-2xl mx-auto">
    <div class="mb-8">
        <div class="flex items-center space-x-3">
            <a href="{{ route('dashboard.domains') }}"
               class="text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 rounded">
                <i data-lucide="arrow-left" class="w-5 h-5"></i>
                <span class="sr-only">Back to domains</span>
            </a>
            <div>
                <h1 class="text-2xl font-bold text-gray-900">Scan your domain</h1>
                <p class="text-gray-600 mt-1">Enter a domain to run your first MXScan security check.</p>
            </div>
        </div>
    </div>

    <div class="bg-white rounded-lg shadow-sm p-6" x-data="{ advancedOpen: false }">
        <form method="POST" action="{{ route('dashboard.domains.store') }}" class="space-y-6" id="add-domain-form">
            @csrf

            <div>
                <label for="domain" class="block text-sm font-medium text-gray-700 mb-2">
                    Domain <span class="text-red-500">*</span>
                </label>
                <div class="relative">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <i data-lucide="globe" class="h-5 w-5 text-gray-400"></i>
                    </div>
                    <input type="text"
                           name="domain"
                           id="domain"
                           value="{{ old('domain') }}"
                           class="block w-full pl-10 pr-3 py-2 border @error('domain') border-red-300 @else border-gray-300 @enderror rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                           placeholder="example.com"
                           required
                           autocomplete="off"
                           aria-describedby="domain-help @error('domain') domain-error @enderror">
                </div>
                @error('domain')
                    <p id="domain-error" class="mt-1 text-sm text-red-600" role="alert">{{ $message }}</p>
                @enderror
                <p id="domain-help" class="mt-1 text-sm text-gray-500">
                    Example: example.com — protocol and paths are removed automatically.
                </p>
                @unless($isPaid ?? false)
                <p class="mt-2 text-sm text-blue-700 bg-blue-50 border border-blue-100 rounded-md px-3 py-2">
                    Free plan includes one domain and manual full security scans.
                </p>
                @endunless
            </div>

            @if($isPaid ?? false)
            <div class="border border-gray-200 rounded-lg">
                <button type="button"
                        id="advanced-options-toggle"
                        class="w-full flex items-center justify-between px-4 py-3 text-left text-sm font-medium text-gray-900 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 rounded-lg"
                        @click="advancedOpen = !advancedOpen"
                        :aria-expanded="advancedOpen.toString()"
                        aria-controls="advanced-options-panel">
                    <span>Advanced options</span>
                    <i data-lucide="chevron-down" class="h-4 w-4 text-gray-500 transition-transform" :class="advancedOpen && 'rotate-180'"></i>
                </button>
                <div id="advanced-options-panel"
                     x-show="advancedOpen"
                     x-cloak
                     class="px-4 pb-4 space-y-6 border-t border-gray-100">
                    <div class="pt-4">
                        <label for="environment" class="block text-sm font-medium text-gray-700 mb-2">
                            Environment
                        </label>
                        <select name="environment"
                                id="environment"
                                class="block w-full px-3 py-2 border @error('environment') border-red-300 @else border-gray-300 @enderror rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                            <option value="prod" {{ old('environment', 'prod') === 'prod' ? 'selected' : '' }}>
                                Production
                            </option>
                            <option value="dev" {{ old('environment') === 'dev' ? 'selected' : '' }}>
                                Development
                            </option>
                        </select>
                        @error('environment')
                            <p class="mt-1 text-sm text-red-600" role="alert">{{ $message }}</p>
                        @enderror
                    </div>

                    <div>
                        <p class="block text-sm font-medium text-gray-700 mb-3" id="services-legend">Monitoring Services</p>
                        <div class="space-y-3" role="group" aria-labelledby="services-legend">
                            <label class="flex items-start">
                                <input type="checkbox" name="service_dns" id="service_dns" value="1" checked
                                       class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <span class="ml-3">
                                    <span class="block text-sm font-medium text-gray-900">DNS Security</span>
                                    <span class="block text-sm text-gray-500">Monitor MX, SPF, DMARC, TLS-RPT, and MTA-STS records</span>
                                </span>
                            </label>
                            <label class="flex items-start">
                                <input type="checkbox" name="service_spf" id="service_spf" value="1" checked
                                       class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <span class="ml-3">
                                    <span class="block text-sm font-medium text-gray-900">SPF Analysis</span>
                                    <span class="block text-sm text-gray-500">Track SPF record changes and DNS lookup counts</span>
                                </span>
                            </label>
                            <label class="flex items-start">
                                <input type="checkbox" name="service_blacklist" id="service_blacklist" value="1" checked
                                       class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <span class="ml-3">
                                    <span class="block text-sm font-medium text-gray-900">Blacklist Monitoring</span>
                                    <span class="block text-sm text-gray-500">Check against RBL providers</span>
                                </span>
                            </label>
                            <label class="flex items-start">
                                <input type="checkbox" name="service_delivery" id="service_delivery" value="1"
                                       class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <span class="ml-3">
                                    <span class="block text-sm font-medium text-gray-900">Delivery Monitoring</span>
                                    <span class="block text-sm text-gray-500">Track email delivery times and authentication results</span>
                                </span>
                            </label>
                            <label class="flex items-start">
                                <input type="checkbox" name="service_domain_expiry" id="service_domain_expiry" value="1" checked
                                       class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <span class="ml-3">
                                    <span class="block text-sm font-medium text-gray-900">Domain Renewal Monitoring</span>
                                    <span class="block text-sm text-gray-500">Alerts before domain expiry</span>
                                </span>
                            </label>
                            <label class="flex items-start">
                                <input type="checkbox" name="service_ssl_expiry" id="service_ssl_expiry" value="1" checked
                                       class="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <span class="ml-3">
                                    <span class="block text-sm font-medium text-gray-900">SSL Certificate Monitoring</span>
                                    <span class="block text-sm text-gray-500">Alerts before SSL expiry</span>
                                </span>
                            </label>
                        </div>
                    </div>

                    <div>
                        <p class="block text-sm font-medium text-gray-700 mb-3" id="schedule-legend">Scan Schedule</p>
                        <div class="space-y-3" role="radiogroup" aria-labelledby="schedule-legend">
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
                                   class="block w-40 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                        </div>
                    </div>
                </div>
            </div>
            @endif

            <input type="hidden" name="schedule" id="hidden_schedule" value="off">

            <div class="flex items-center justify-end space-x-3 pt-2">
                <a href="{{ route('dashboard') }}"
                   class="mx-btn mx-btn-secondary">
                    Cancel
                </a>
                <button type="submit"
                        class="mx-btn mx-btn-primary">
                    <i data-lucide="scan" class="w-4 h-4"></i>
                    Scan domain
                </button>
            </div>
        </form>
    </div>
</div>

<script>
    lucide.createIcons();

    function normalizeDomainInput(value) {
        let v = (value || '').trim();
        v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
        v = v.replace(/^[^@]+@/, '');
        v = v.split(/[/?#]/)[0];
        v = v.replace(/:\d+$/, '');
        v = v.toLowerCase().replace(/\.$/, '');
        if (v.startsWith('www.')) v = v.slice(4);
        return v;
    }

    document.getElementById('domain').addEventListener('blur', function(e) {
        e.target.value = normalizeDomainInput(e.target.value);
    });

    @if($isPaid ?? false)
    const scheduleRadios = document.querySelectorAll('input[name="schedule_type"]');
    const timePicker = document.getElementById('time-picker');
    scheduleRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            timePicker.classList.toggle('hidden', this.value === 'off');
            updateHiddenFields();
        });
    });

    function updateHiddenFields() {
        const services = [];
        if (document.getElementById('service_dns').checked) services.push('dns');
        if (document.getElementById('service_spf').checked) services.push('spf');
        if (document.getElementById('service_blacklist').checked) services.push('blacklist');
        if (document.getElementById('service_delivery').checked) services.push('delivery');
        if (document.getElementById('service_domain_expiry').checked) services.push('domain_expiry');
        if (document.getElementById('service_ssl_expiry').checked) services.push('ssl_expiry');

        document.querySelectorAll('input[name="services[]"]').forEach(input => input.remove());
        const form = document.getElementById('add-domain-form');
        services.forEach(service => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'services[]';
            input.value = service;
            form.appendChild(input);
        });

        const scheduleType = document.querySelector('input[name="schedule_type"]:checked').value;
        let scheduleValue = scheduleType;
        if (scheduleType !== 'off') {
            scheduleValue = scheduleType + '@' + document.getElementById('schedule_time').value;
        }
        document.getElementById('hidden_schedule').value = scheduleValue;
    }

    document.querySelectorAll('#advanced-options-panel input').forEach(el => {
        el.addEventListener('change', updateHiddenFields);
    });
    document.getElementById('add-domain-form').addEventListener('submit', function() {
        document.getElementById('domain').value = normalizeDomainInput(document.getElementById('domain').value);
        updateHiddenFields();
    });
    updateHiddenFields();
    @else
    document.getElementById('add-domain-form').addEventListener('submit', function() {
        document.getElementById('domain').value = normalizeDomainInput(document.getElementById('domain').value);
    });
    @endif
</script>
@endsection
