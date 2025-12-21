<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ config('app.name', 'Laravel') }} - Admin Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <div class="flex">
            <!-- Admin Sidebar -->
            <div class="hidden md:flex md:w-64 md:flex-col">
                <div class="flex flex-col flex-grow pt-5 overflow-y-auto bg-white border-r border-gray-200">
                    <div class="flex items-center flex-shrink-0 px-4">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <i data-lucide="shield-check" class="h-8 w-8 text-red-600"></i>
                            </div>
                            <div class="ml-3">
                                <h1 class="text-xl font-bold text-gray-900">EmailSec Admin</h1>
                            </div>
                        </div>
                    </div>
                    <div class="mt-8 flex-grow flex flex-col">
                        <nav class="flex-1 px-2 pb-4 space-y-1">
                            <a href="{{ route('admin.dashboard') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.dashboard') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="layout-dashboard" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.dashboard') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Dashboard
                            </a>
                            <a href="{{ route('admin.users.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.users.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="users" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.users.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Users
                            </a>
                            <a href="{{ route('admin.domains.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.domains.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="globe" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.domains.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Domains
                            </a>
                            <a href="{{ route('admin.scans.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.scans.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="search" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.scans.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Scans
                            </a>
                            <a href="{{ route('admin.plans.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.plans.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="credit-card" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.plans.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Plans
                            </a>
                            <a href="{{ route('admin.subscriptions.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.subscriptions.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="repeat" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.subscriptions.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Subscriptions
                            </a>
                            <a href="{{ route('admin.invoices.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.invoices.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="receipt" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.invoices.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Invoices
                            </a>
                            <a href="{{ route('admin.audit.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.audit.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="file-text" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.audit.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Audit Logs
                            </a>
                            
                            <a href="{{ route('admin.settings.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('admin.settings.*') ? 'bg-red-100 text-red-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="settings" class="mr-3 h-5 w-5 {{ request()->routeIs('admin.settings.*') ? 'text-red-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Settings
                            </a>
                        </nav>
                        
                        <!-- Back to User Dashboard -->
                        <div class="px-2 pb-4 border-t border-gray-200 pt-4">
                            <a href="{{ route('dashboard') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md text-gray-600 hover:bg-gray-50 hover:text-gray-900">
                                <i data-lucide="arrow-left" class="mr-3 h-5 w-5 text-gray-400 group-hover:text-gray-500"></i>
                                Back to User Panel
                            </a>
                        </div>
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
                                class="md:hidden inline-flex items-center justify-center p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-red-500"
                                x-data="{ sidebarOpen: false }" 
                                @click="sidebarOpen = !sidebarOpen">
                            <i data-lucide="menu" class="h-6 w-6"></i>
                        </button>

                        <!-- Page title -->
                        <div class="flex-1 min-w-0">
                            <h2 class="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl sm:truncate">
                                @yield('page-title', 'Admin Dashboard')
                            </h2>
                        </div>

                        <!-- Admin badge & user menu -->
                        <div class="ml-4 flex items-center md:ml-6" x-data="{ dropdownOpen: false }">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 mr-4">
                                Admin
                            </span>
                            <div class="relative">
                                <button type="button" 
                                        class="max-w-xs bg-white flex items-center text-sm rounded-full focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500" 
                                        @click="dropdownOpen = !dropdownOpen">
                                    <span class="sr-only">Open user menu</span>
                                    <div class="h-8 w-8 rounded-full bg-red-600 flex items-center justify-center">
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

                <!-- Impersonation Banner -->
                @if(session('impersonator_id'))
                <div class="bg-amber-100 text-amber-800 text-sm px-4 py-2 flex items-center justify-between">
                    <div class="flex items-center">
                        <i data-lucide="user-check" class="h-4 w-4 mr-2"></i>
                        <span>Impersonating as {{ auth()->user()->email }}</span>
                    </div>
                    <form action="{{ route('admin.impersonate.stop') }}" method="post" class="inline">
                        @csrf
                        <button class="underline hover:no-underline">Stop Impersonation</button>
                    </form>
                </div>
                @endif

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

                <!-- Main content area -->
                <main class="flex-1 p-4 sm:p-6 lg:p-8">
                    @yield('content')
                </main>
            </div>
        </div>
    </div>

    <script>
        lucide.createIcons();
    </script>
</body>
</html>