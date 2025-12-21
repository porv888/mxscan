<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ config('app.name', 'Laravel') }} - Email Security Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen" 
         x-data="{
            showUpgrade: false,
            showToast: false,
            toastText: '',
            toastType: 'info'
         }"
         @open-upgrade.window="showUpgrade = true"
         @toast.window="showToast = true; toastText = $event.detail.text; toastType = $event.detail.type; setTimeout(() => showToast = false, 3000)">
        <div class="flex">
            <!-- Sidebar -->
            <div class="hidden md:flex md:w-64 md:flex-col">
                <div class="flex flex-col flex-grow pt-5 overflow-y-auto bg-white border-r border-gray-200">
                    <div class="flex items-center flex-shrink-0 px-4">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <i data-lucide="shield-check" class="h-8 w-8 text-blue-600"></i>
                            </div>
                            <div class="ml-3">
                                <h1 class="text-xl font-bold text-gray-900">EmailSec</h1>
                            </div>
                        </div>
                    </div>
                    <div class="mt-8 flex-grow flex flex-col">
                        <nav class="flex-1 px-2 pb-4 space-y-1">
                            <a href="{{ route('dashboard') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="layout-dashboard" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Dashboard
                            </a>
                            <a href="{{ route('dashboard.domains') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard.domains*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="globe" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard.domains*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Domains
                            </a>
                            <a href="{{ route('schedules.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('schedules*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="calendar" class="mr-3 h-5 w-5 {{ request()->routeIs('schedules*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Schedules
                            </a>
                            <a href="{{ route('dashboard.scans') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard.scans*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="search" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard.scans*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Scans
                            </a>
                            
                            @if(auth()->user()->canUseMonitoring())
                                <a href="{{ route('monitoring.incidents') }}" 
                                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('monitoring.incidents*') || request()->routeIs('monitoring.snapshots*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                    <i data-lucide="alert-triangle" class="mr-3 h-5 w-5 {{ request()->routeIs('monitoring.incidents*') || request()->routeIs('monitoring.snapshots*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                    Monitoring
                                </a>
                            @endif
                            
                            <a href="{{ route('delivery-monitoring.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('delivery-monitoring.*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="mail" class="mr-3 h-5 w-5 {{ request()->routeIs('delivery-monitoring.*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Delivery
                            </a>
                            
                            <a href="{{ route('dashboard.profile') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard.profile') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="user" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard.profile') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Profile
                            </a>
                        </nav>
                    </div>
                </div>
            </div>

            <!-- Main content -->
            <div class="flex flex-col flex-1">
                <!-- Top navigation -->
                <header class="bg-white shadow-sm border-b border-gray-200">
                    <div class="flex items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
                        <!-- Mobile menu button -->
                        <button type="button" 
                                class="md:hidden inline-flex items-center justify-center p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500"
                                x-data="{ sidebarOpen: false }" 
                                @click="sidebarOpen = !sidebarOpen">
                            <i data-lucide="menu" class="h-6 w-6"></i>
                        </button>

                        <!-- Page title -->
                        <div class="flex-1 min-w-0">
                            <h2 class="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl sm:truncate">
                                @yield('page-title', 'Dashboard')
                            </h2>
                        </div>

                        <!-- User menu -->
                        <div class="ml-4 flex items-center md:ml-6" x-data="{ dropdownOpen: false }">
                            <div class="relative">
                                <button type="button" 
                                        class="max-w-xs bg-white flex items-center text-sm rounded-full focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500" 
                                        @click="dropdownOpen = !dropdownOpen">
                                    <span class="sr-only">Open user menu</span>
                                    <div class="h-8 w-8 rounded-full bg-blue-600 flex items-center justify-center">
                                        <span class="text-sm font-medium text-white">{{ substr(Auth::user()->name, 0, 1) }}</span>
                                    </div>
                                    <span class="hidden md:ml-3 md:block">
                                        <span class="text-sm font-medium text-gray-700">{{ Auth::user()->name }}</span>
                                    </span>
                                    <i data-lucide="chevron-down" class="hidden md:block ml-2 h-4 w-4 text-gray-400"></i>
                                </button>

                                <div x-show="dropdownOpen" 
                                     x-transition:enter="transition ease-out duration-100"
                                     x-transition:enter-start="transform opacity-0 scale-95"
                                     x-transition:enter-end="transform opacity-100 scale-100"
                                     x-transition:leave="transition ease-in duration-75"
                                     x-transition:leave-start="transform opacity-100 scale-100"
                                     x-transition:leave-end="transform opacity-0 scale-95"
                                     @click.away="dropdownOpen = false"
                                     class="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50">
                                    
                                    <a href="{{ route('dashboard.profile') }}" 
                                       class="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                        <i data-lucide="user" class="w-4 h-4 mr-2"></i>
                                        Profile
                                    </a>
                                    
                                    <a href="{{ route('settings.notifications') }}" 
                                       class="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                        <i data-lucide="bell" class="w-4 h-4 mr-2"></i>
                                        Notifications
                                    </a>
                                    
                                    <a href="{{ route('billing') }}" 
                                       class="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                        <i data-lucide="credit-card" class="w-4 h-4 mr-2"></i>
                                        Billing
                                    </a>
                                    
                                    @if(auth()->user()->isAdmin())
                                        <div class="border-t border-gray-100 my-1"></div>
                                        <a href="{{ route('admin.dashboard') }}" 
                                           class="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                            <i data-lucide="settings" class="w-4 h-4 mr-2"></i>
                                            Admin Panel
                                        </a>
                                    @endif
                                    
                                    <div class="border-t border-gray-100 my-1"></div>
                                    
                                    <form method="POST" action="{{ route('logout') }}" class="block">
                                        @csrf
                                        <button type="submit" 
                                                class="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                            <i data-lucide="log-out" class="w-4 h-4 mr-2"></i>
                                            Logout
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <!-- Flash Messages -->
                @if (session('success'))
                    <div class="mx-4 mt-4 p-4 bg-green-50 border border-green-200 rounded-lg" x-data="{ show: true }" x-show="show">
                        <div class="flex items-center justify-between">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    <i data-lucide="check-circle" class="h-5 w-5 text-green-400"></i>
                                </div>
                                <div class="ml-3">
                                    <p class="text-sm text-green-800">{{ session('success') }}</p>
                                </div>
                            </div>
                            <button @click="show = false" class="text-green-400 hover:text-green-600">
                                <i data-lucide="x" class="h-4 w-4"></i>
                            </button>
                        </div>
                    </div>
                @endif

                @if (session('error'))
                    <div class="mx-4 mt-4 p-4 bg-red-50 border border-red-200 rounded-lg" x-data="{ show: true }" x-show="show">
                        <div class="flex items-center justify-between">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    <i data-lucide="alert-circle" class="h-5 w-5 text-red-400"></i>
                                </div>
                                <div class="ml-3">
                                    <p class="text-sm text-red-800">{{ session('error') }}</p>
                                </div>
                            </div>
                            <button @click="show = false" class="text-red-400 hover:text-red-600">
                                <i data-lucide="x" class="h-4 w-4"></i>
                            </button>
                        </div>
                    </div>
                @endif

                @if (session('status'))
                    <div class="mx-4 mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg" x-data="{ show: true }" x-show="show">
                        <div class="flex items-center justify-between">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    <i data-lucide="info" class="h-5 w-5 text-blue-400"></i>
                                </div>
                                <div class="ml-3">
                                    <p class="text-sm text-blue-800">{{ session('status') }}</p>
                                </div>
                            </div>
                            <button @click="show = false" class="text-blue-400 hover:text-blue-600">
                                <i data-lucide="x" class="h-4 w-4"></i>
                            </button>
                        </div>
                    </div>
                @endif

                <!-- Main content area -->
                <main class="flex-1 p-4 sm:p-6 lg:p-8">
                    @yield('content')
                </main>
            </div>
        </div>

        <!-- Toast Notification -->
        <div x-show="showToast"
             x-transition:enter="transition ease-out duration-300"
             x-transition:enter-start="transform translate-x-full opacity-0"
             x-transition:enter-end="transform translate-x-0 opacity-100"
             x-transition:leave="transition ease-in duration-200"
             x-transition:leave-start="transform translate-x-0 opacity-100"
             x-transition:leave-end="transform translate-x-full opacity-0"
             class="fixed top-4 right-4 z-50 max-w-sm w-full">
            <div class="rounded-lg shadow-lg p-4"
                 :class="toastType === 'info' ? 'bg-blue-600 text-white' : 
                         toastType === 'success' ? 'bg-green-600 text-white' : 
                         'bg-red-600 text-white'">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i :data-lucide="toastType === 'info' ? 'info' : 
                                        toastType === 'success' ? 'check-circle' : 
                                        'alert-circle'" 
                           class="h-5 w-5"></i>
                    </div>
                    <div class="ml-3 flex-1">
                        <p class="text-sm font-medium" x-text="toastText"></p>
                    </div>
                    <div class="ml-4 flex-shrink-0">
                        <button @click="showToast = false" class="text-white hover:text-gray-200">
                            <i data-lucide="x" class="h-4 w-4"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Upgrade Modal -->
        <div x-show="showUpgrade" 
             x-transition:enter="transition ease-out duration-300"
             x-transition:enter-start="opacity-0"
             x-transition:enter-end="opacity-100"
             x-transition:leave="transition ease-in duration-200"
             x-transition:leave-start="opacity-100"
             x-transition:leave-end="opacity-0"
             class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div class="bg-white rounded-lg shadow-xl max-w-md w-full"
                 x-transition:enter="transition ease-out duration-300"
                 x-transition:enter-start="transform scale-95 opacity-0"
                 x-transition:enter-end="transform scale-100 opacity-100"
                 x-transition:leave="transition ease-in duration-200"
                 x-transition:leave-start="transform scale-100 opacity-100"
                 x-transition:leave-end="transform scale-95 opacity-0"
                 @click.away="showUpgrade = false">
                <div class="p-6">
                    <div class="flex items-center mb-4">
                        <div class="flex-shrink-0">
                            <i data-lucide="lock" class="h-8 w-8 text-amber-500"></i>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-lg font-semibold text-gray-900">Upgrade Required</h3>
                        </div>
                    </div>
                    <p class="text-sm text-gray-600 mb-6">
                        Blacklist monitoring is available with our Premium and Ultra plans. 
                        Upgrade now to unlock advanced security features and protect your domain reputation.
                    </p>
                    <div class="flex justify-end space-x-3">
                        <button @click="showUpgrade = false" 
                                class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors">
                            Maybe Later
                        </button>
                        <a href="{{ route('pricing') }}" 
                           class="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors">
                            View Plans
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        lucide.createIcons();
        
        // Reinitialize Lucide icons after Alpine.js updates
        document.addEventListener('alpine:init', () => {
            Alpine.effect(() => {
                setTimeout(() => lucide.createIcons(), 100);
            });
        });
    </script>
</body>
</html>
