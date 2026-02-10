@extends('layouts.app')

@section('page-title', 'Tools')

@section('content')
<div class="space-y-6">
    <div>
        <h1 class="text-2xl font-bold text-gray-900">Email Security Tools</h1>
        <p class="text-gray-600 mt-1">Quick diagnostic tools to check and improve your email security</p>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- SMTP Test -->
        <a href="{{ route('tools.smtp') }}" class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md hover:border-blue-300 transition-all group">
            <div class="flex items-center space-x-3 mb-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center group-hover:bg-blue-200 transition-colors">
                    <i data-lucide="wifi" class="w-5 h-5 text-blue-600"></i>
                </div>
                <h3 class="text-lg font-semibold text-gray-900">SMTP Test</h3>
            </div>
            <p class="text-sm text-gray-600">Test SMTP connectivity to your mail servers. Check banners, EHLO capabilities, and STARTTLS support.</p>
        </a>

        <!-- BIMI Check -->
        <a href="{{ route('tools.bimi') }}" class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md hover:border-green-300 transition-all group">
            <div class="flex items-center space-x-3 mb-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-green-100 flex items-center justify-center group-hover:bg-green-200 transition-colors">
                    <i data-lucide="image" class="w-5 h-5 text-green-600"></i>
                </div>
                <h3 class="text-lg font-semibold text-gray-900">BIMI Check</h3>
            </div>
            <p class="text-sm text-gray-600">Validate your BIMI DNS record and SVG logo. Check compliance with the BIMI standard for brand display in inboxes.</p>
        </a>

        <!-- SPF Wizard -->
        <a href="{{ route('tools.spf') }}" class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md hover:border-amber-300 transition-all group">
            <div class="flex items-center space-x-3 mb-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-amber-100 flex items-center justify-center group-hover:bg-amber-200 transition-colors">
                    <i data-lucide="wand-2" class="w-5 h-5 text-amber-600"></i>
                </div>
                <h3 class="text-lg font-semibold text-gray-900">SPF Wizard</h3>
            </div>
            <p class="text-sm text-gray-600">Build an SPF record from scratch. Select your email providers, add custom IPs, and get a ready-to-use record.</p>
        </a>

        <!-- DKIM Lookup -->
        <a href="{{ route('tools.dkim') }}" class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md hover:border-purple-300 transition-all group">
            <div class="flex items-center space-x-3 mb-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-purple-100 flex items-center justify-center group-hover:bg-purple-200 transition-colors">
                    <i data-lucide="key" class="w-5 h-5 text-purple-600"></i>
                </div>
                <h3 class="text-lg font-semibold text-gray-900">DKIM Lookup</h3>
            </div>
            <p class="text-sm text-gray-600">Check DKIM public keys in DNS. Probe common selectors or look up a specific one, with key size analysis.</p>
        </a>
    </div>
</div>
@endsection
