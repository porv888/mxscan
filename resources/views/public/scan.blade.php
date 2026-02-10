<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>MXScan - Email Security Scanner</title>
    <meta name="description" content="Check your domain's email security in seconds. Free SPF, DKIM, DMARC, MTA-STS and TLS-RPT analysis.">
    <meta property="og:title" content="MXScan - Email Security Scanner">
    <meta property="og:description" content="Check your domain's email security in seconds. Free SPF, DKIM, DMARC analysis.">
    <meta property="og:type" content="website">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
</head>
<body class="bg-gray-50">

    <!-- Nav -->
    <nav class="bg-white border-b border-gray-200">
        <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
            <div class="flex items-center space-x-2">
                <i data-lucide="shield-check" class="h-7 w-7 text-blue-600"></i>
                <span class="text-xl font-bold text-gray-900">MXScan</span>
            </div>
            <div class="flex items-center space-x-4">
                <a href="{{ route('pricing') }}" class="text-sm text-gray-600 hover:text-gray-900">Pricing</a>
                <a href="{{ route('login') }}" class="text-sm text-gray-600 hover:text-gray-900">Log in</a>
                <a href="{{ route('register') }}" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg transition-colors">Sign up free</a>
            </div>
        </div>
    </nav>

    <!-- Hero -->
    <section class="bg-gradient-to-b from-white to-blue-50 pt-16 pb-20">
        <div class="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
            <h1 class="text-4xl sm:text-5xl font-extrabold text-gray-900 tracking-tight mb-4">
                Check your domain's<br>
                <span class="text-blue-600">email security</span> in seconds
            </h1>
            <p class="text-lg text-gray-600 mb-10 max-w-2xl mx-auto">
                Free instant scan for SPF, DKIM, DMARC, MTA-STS and TLS-RPT. Get a security score and actionable recommendations.
            </p>

            <!-- Scan Form -->
            <form method="POST" action="{{ route('public.scan.run') }}" class="max-w-xl mx-auto">
                @csrf
                <div class="flex shadow-lg rounded-xl overflow-hidden border border-gray-200">
                    <input type="text" name="domain" value="{{ old('domain') }}"
                           placeholder="Enter your domain, e.g. example.com"
                           required autofocus
                           class="flex-1 px-5 py-4 text-lg border-0 focus:ring-0 focus:outline-none">
                    <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-8 py-4 text-lg font-semibold transition-colors flex items-center space-x-2">
                        <i data-lucide="search" class="w-5 h-5"></i>
                        <span>Scan</span>
                    </button>
                </div>
                @error('domain')
                    <p class="mt-2 text-sm text-red-600">{{ $message }}</p>
                @enderror
            </form>
        </div>
    </section>

    <!-- Features -->
    <section class="py-16">
        <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
            <h2 class="text-2xl font-bold text-center text-gray-900 mb-12">What we check</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
                <div class="text-center">
                    <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                        <i data-lucide="mail" class="w-6 h-6 text-blue-600"></i>
                    </div>
                    <h3 class="font-semibold text-gray-900 mb-2">MX Records</h3>
                    <p class="text-sm text-gray-600">Verify your mail server configuration is correct and reachable.</p>
                </div>
                <div class="text-center">
                    <div class="w-12 h-12 bg-green-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                        <i data-lucide="shield" class="w-6 h-6 text-green-600"></i>
                    </div>
                    <h3 class="font-semibold text-gray-900 mb-2">SPF</h3>
                    <p class="text-sm text-gray-600">Check that your Sender Policy Framework record is properly configured.</p>
                </div>
                <div class="text-center">
                    <div class="w-12 h-12 bg-purple-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                        <i data-lucide="key" class="w-6 h-6 text-purple-600"></i>
                    </div>
                    <h3 class="font-semibold text-gray-900 mb-2">DKIM</h3>
                    <p class="text-sm text-gray-600">Detect DKIM signing keys published in your DNS for message integrity.</p>
                </div>
                <div class="text-center">
                    <div class="w-12 h-12 bg-amber-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                        <i data-lucide="file-check" class="w-6 h-6 text-amber-600"></i>
                    </div>
                    <h3 class="font-semibold text-gray-900 mb-2">DMARC</h3>
                    <p class="text-sm text-gray-600">Validate your DMARC policy to protect against spoofing and phishing.</p>
                </div>
                <div class="text-center">
                    <div class="w-12 h-12 bg-teal-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                        <i data-lucide="lock" class="w-6 h-6 text-teal-600"></i>
                    </div>
                    <h3 class="font-semibold text-gray-900 mb-2">MTA-STS</h3>
                    <p class="text-sm text-gray-600">Check if your domain enforces encrypted email delivery via MTA-STS.</p>
                </div>
                <div class="text-center">
                    <div class="w-12 h-12 bg-rose-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                        <i data-lucide="bar-chart-3" class="w-6 h-6 text-rose-600"></i>
                    </div>
                    <h3 class="font-semibold text-gray-900 mb-2">TLS-RPT</h3>
                    <p class="text-sm text-gray-600">Verify TLS reporting is enabled to catch delivery encryption failures.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA -->
    <section class="bg-blue-600 py-14">
        <div class="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
            <h2 class="text-2xl font-bold text-white mb-3">Need continuous monitoring?</h2>
            <p class="text-blue-100 mb-6">Sign up for free to monitor your domains 24/7 with automated scans, blacklist checking, delivery testing, and DMARC visibility.</p>
            <a href="{{ route('register') }}" class="inline-flex items-center bg-white text-blue-600 font-semibold px-6 py-3 rounded-lg hover:bg-blue-50 transition-colors">
                Get started free
                <i data-lucide="arrow-right" class="w-4 h-4 ml-2"></i>
            </a>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-white border-t border-gray-200 py-8">
        <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between text-sm text-gray-500">
            <span>&copy; {{ date('Y') }} MXScan. All rights reserved.</span>
            <div class="flex space-x-4">
                <a href="{{ route('terms') }}" class="hover:text-gray-700">Terms</a>
                <a href="{{ route('privacy') }}" class="hover:text-gray-700">Privacy</a>
                <a href="{{ route('pricing') }}" class="hover:text-gray-700">Pricing</a>
            </div>
        </div>
    </footer>

    <script>lucide.createIcons();</script>
</body>
</html>
