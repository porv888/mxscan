<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>MXScan - Results for {{ $domain }}</title>
    <meta name="description" content="Email security scan results for {{ $domain }}. Score: {{ $results['score'] }}/100.">
    <meta property="og:title" content="MXScan - {{ $domain }} scored {{ $results['score'] }}/100">
    <meta property="og:description" content="Email security scan results for {{ $domain }}">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
</head>
<body class="bg-gray-50">

    <!-- Nav -->
    <nav class="bg-white border-b border-gray-200">
        <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
            <a href="{{ route('public.scan') }}" class="flex items-center space-x-2">
                <i data-lucide="shield-check" class="h-7 w-7 text-blue-600"></i>
                <span class="text-xl font-bold text-gray-900">MXScan</span>
            </a>
            <div class="flex items-center space-x-4">
                <a href="{{ route('pricing') }}" class="text-sm text-gray-600 hover:text-gray-900">Pricing</a>
                <a href="{{ route('login') }}" class="text-sm text-gray-600 hover:text-gray-900">Log in</a>
                <a href="{{ route('register') }}" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg transition-colors">Sign up free</a>
            </div>
        </div>
    </nav>

    <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <!-- Scan Another -->
        <form method="POST" action="{{ route('public.scan.run') }}" class="mb-8">
            @csrf
            <div class="flex shadow-sm rounded-lg overflow-hidden border border-gray-200">
                <input type="text" name="domain" value="{{ $domain }}" placeholder="Enter domain"
                       required class="flex-1 px-4 py-3 text-sm border-0 focus:ring-0 focus:outline-none">
                <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 text-sm font-medium transition-colors">
                    Scan Again
                </button>
            </div>
        </form>

        <!-- Score Card -->
        @php
            $score = $results['score'];
            $scoreColor = $score >= 80 ? 'green' : ($score >= 50 ? 'amber' : 'red');
            $scoreLabel = $score >= 80 ? 'Good' : ($score >= 50 ? 'Needs Improvement' : 'At Risk');
        @endphp
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-8 mb-8">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-2xl font-bold text-gray-900">{{ $domain }}</h1>
                    <p class="text-gray-500 mt-1">Email Security Score</p>
                </div>
                <div class="text-center">
                    <div class="w-24 h-24 rounded-full border-4 flex items-center justify-center
                        {{ $scoreColor === 'green' ? 'border-green-500 bg-green-50' : ($scoreColor === 'amber' ? 'border-amber-500 bg-amber-50' : 'border-red-500 bg-red-50') }}">
                        <span class="text-3xl font-bold {{ $scoreColor === 'green' ? 'text-green-700' : ($scoreColor === 'amber' ? 'text-amber-700' : 'text-red-700') }}">
                            {{ $score }}
                        </span>
                    </div>
                    <p class="text-sm font-medium mt-2 {{ $scoreColor === 'green' ? 'text-green-700' : ($scoreColor === 'amber' ? 'text-amber-700' : 'text-red-700') }}">
                        {{ $scoreLabel }}
                    </p>
                </div>
            </div>
        </div>

        <!-- Records Status -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mb-8">
            <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                <h2 class="text-lg font-semibold text-gray-900">DNS Records</h2>
            </div>
            <div class="divide-y divide-gray-100">
                @php
                    $checks = [
                        'MX' => ['label' => 'MX Records', 'icon' => 'mail', 'desc' => 'Mail server configuration'],
                        'SPF' => ['label' => 'SPF', 'icon' => 'shield', 'desc' => 'Sender Policy Framework'],
                        'DKIM' => ['label' => 'DKIM', 'icon' => 'key', 'desc' => 'DomainKeys Identified Mail'],
                        'DMARC' => ['label' => 'DMARC', 'icon' => 'file-check', 'desc' => 'Domain-based Message Authentication'],
                        'TLS-RPT' => ['label' => 'TLS-RPT', 'icon' => 'bar-chart-3', 'desc' => 'TLS Reporting'],
                        'MTA-STS' => ['label' => 'MTA-STS', 'icon' => 'lock', 'desc' => 'Mail Transfer Agent Strict Transport Security'],
                    ];
                @endphp

                @foreach($checks as $key => $check)
                    @php
                        $record = $results['records'][$key] ?? null;
                        $found = $record && $record['status'] === 'found';
                    @endphp
                    <div class="px-6 py-4 flex items-center justify-between">
                        <div class="flex items-center space-x-4">
                            <div class="w-10 h-10 rounded-lg flex items-center justify-center {{ $found ? 'bg-green-100' : 'bg-red-100' }}">
                                <i data-lucide="{{ $check['icon'] }}" class="w-5 h-5 {{ $found ? 'text-green-600' : 'text-red-600' }}"></i>
                            </div>
                            <div>
                                <h3 class="text-sm font-semibold text-gray-900">{{ $check['label'] }}</h3>
                                <p class="text-xs text-gray-500">{{ $check['desc'] }}</p>
                            </div>
                        </div>
                        <div class="flex items-center space-x-3">
                            @if($found)
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                    <i data-lucide="check" class="w-3 h-3 mr-1"></i> Found
                                </span>
                                @if($key === 'DKIM' && is_array($record['data']))
                                    <span class="text-xs text-gray-500">{{ count($record['data']) }} selector{{ count($record['data']) > 1 ? 's' : '' }}</span>
                                @endif
                            @else
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                    <i data-lucide="x" class="w-3 h-3 mr-1"></i> Missing
                                </span>
                            @endif
                        </div>
                    </div>
                @endforeach
            </div>
        </div>

        <!-- Recommendations (blurred for non-auth) -->
        @if(!empty($results['recommendations']))
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mb-8 relative">
                <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                    <h2 class="text-lg font-semibold text-gray-900">Recommendations ({{ count($results['recommendations']) }})</h2>
                </div>
                <div class="relative">
                    <!-- Show first recommendation clearly -->
                    @if(count($results['recommendations']) > 0)
                        @php $rec = $results['recommendations'][0]; @endphp
                        <div class="px-6 py-4 border-b border-gray-100">
                            <div class="flex items-start space-x-3">
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 mt-0.5">{{ $rec['type'] }}</span>
                                <div>
                                    <h4 class="text-sm font-semibold text-gray-900">{{ $rec['title'] }}</h4>
                                    <p class="text-xs text-gray-500 mt-1">{{ $rec['description'] }}</p>
                                </div>
                            </div>
                        </div>
                    @endif

                    <!-- Blur remaining recommendations -->
                    @if(count($results['recommendations']) > 1)
                        <div class="relative">
                            <div class="px-6 py-4 filter blur-sm select-none pointer-events-none">
                                @foreach(array_slice($results['recommendations'], 1, 3) as $rec)
                                    <div class="mb-4">
                                        <div class="flex items-start space-x-3">
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">{{ $rec['type'] }}</span>
                                            <div>
                                                <h4 class="text-sm font-semibold text-gray-700">{{ $rec['title'] }}</h4>
                                                <p class="text-xs text-gray-400 mt-1">{{ $rec['description'] }}</p>
                                            </div>
                                        </div>
                                    </div>
                                @endforeach
                            </div>
                            <div class="absolute inset-0 bg-gradient-to-b from-transparent via-white/70 to-white flex items-end justify-center pb-6">
                                <a href="{{ route('register') }}" class="bg-blue-600 hover:bg-blue-700 text-white font-medium px-6 py-2.5 rounded-lg transition-colors flex items-center space-x-2">
                                    <i data-lucide="lock" class="w-4 h-4"></i>
                                    <span>Sign up free to see all recommendations</span>
                                </a>
                            </div>
                        </div>
                    @endif
                </div>
            </div>
        @endif

        <!-- Monitor CTA -->
        <div class="bg-gradient-to-r from-blue-600 to-blue-700 rounded-xl p-8 text-center">
            <h2 class="text-xl font-bold text-white mb-2">Monitor {{ $domain }} 24/7</h2>
            <p class="text-blue-100 mb-5">Get alerted when DNS records change, your domain gets blacklisted, or certificates expire.</p>
            <a href="{{ route('register') }}" class="inline-flex items-center bg-white text-blue-600 font-semibold px-6 py-3 rounded-lg hover:bg-blue-50 transition-colors">
                Start monitoring free
                <i data-lucide="arrow-right" class="w-4 h-4 ml-2"></i>
            </a>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-white border-t border-gray-200 py-8 mt-12">
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
