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
            toastType: 'info',
            sidebarOpen: false
         }"
         @open-upgrade.window="showUpgrade = true"
         @toast.window="showToast = true; toastText = $event.detail.text; toastType = $event.detail.type; setTimeout(() => showToast = false, 3000)">
        
        <!-- Mobile sidebar overlay -->
        <div x-show="sidebarOpen" 
             x-transition:enter="transition-opacity ease-linear duration-300"
             x-transition:enter-start="opacity-0"
             x-transition:enter-end="opacity-100"
             x-transition:leave="transition-opacity ease-linear duration-300"
             x-transition:leave-start="opacity-100"
             x-transition:leave-end="opacity-0"
             class="fixed inset-0 bg-gray-600 bg-opacity-75 z-40 md:hidden"
             @click="sidebarOpen = false"
             x-cloak></div>

        <!-- Mobile sidebar -->
        <div x-show="sidebarOpen"
             x-transition:enter="transition ease-in-out duration-300 transform"
             x-transition:enter-start="-translate-x-full"
             x-transition:enter-end="translate-x-0"
             x-transition:leave="transition ease-in-out duration-300 transform"
             x-transition:leave-start="translate-x-0"
             x-transition:leave-end="-translate-x-full"
             class="fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-xl md:hidden"
             x-cloak>
            <div class="flex items-center justify-between px-4 pt-5 pb-4 border-b border-gray-200">
                <div class="flex items-center">
                    <i data-lucide="shield-check" class="h-8 w-8 text-blue-600"></i>
                    <h1 class="ml-3 text-xl font-bold text-gray-900">EmailSec</h1>
                </div>
                <button @click="sidebarOpen = false" class="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100">
                    <i data-lucide="x" class="h-6 w-6"></i>
                </button>
            </div>
            <nav class="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
                <a href="{{ route('dashboard') }}" 
                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                    <i data-lucide="layout-dashboard" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                    Dashboard
                </a>
                <a href="{{ route('dashboard.domains') }}" 
                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard.domains*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                    <i data-lucide="globe" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard.domains*') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                    Domains
                </a>
                <a href="{{ route('schedules.index') }}" 
                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('schedules*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                    <i data-lucide="calendar" class="mr-3 h-5 w-5 {{ request()->routeIs('schedules*') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                    Schedules
                </a>
                <a href="{{ route('dashboard.scans') }}" 
                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard.scans*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                    <i data-lucide="search" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard.scans*') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                    Scans
                </a>
                @if(auth()->user()->canUseMonitoring())
                    <a href="{{ route('monitoring.incidents') }}" 
                       class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('monitoring.*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                        <i data-lucide="alert-triangle" class="mr-3 h-5 w-5 {{ request()->routeIs('monitoring.*') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                        Monitoring
                    </a>
                @endif
                <a href="{{ route('delivery-monitoring.index') }}" 
                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('delivery-monitoring.*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                    <i data-lucide="mail" class="mr-3 h-5 w-5 {{ request()->routeIs('delivery-monitoring.*') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                    Delivery
                </a>
                <a href="{{ route('dmarc.index') }}" 
                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dmarc.*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                    <i data-lucide="file-bar-chart" class="mr-3 h-5 w-5 {{ request()->routeIs('dmarc.*') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                    DMARC Activity
                </a>
                <a href="{{ route('dashboard.profile') }}" 
                   class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dashboard.profile') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                    <i data-lucide="user" class="mr-3 h-5 w-5 {{ request()->routeIs('dashboard.profile') ? 'text-blue-500' : 'text-gray-400' }}"></i>
                    Profile
                </a>
            </nav>
        </div>

        <div class="flex">
            <!-- Desktop Sidebar -->
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
                                   class="group flex items-center justify-between px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('monitoring.incidents*') || request()->routeIs('monitoring.snapshots*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                    <span class="flex items-center">
                                        <i data-lucide="alert-triangle" class="mr-3 h-5 w-5 {{ request()->routeIs('monitoring.incidents*') || request()->routeIs('monitoring.snapshots*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                        Monitoring
                                    </span>
                                    @if(($sidebarIncidentCount ?? 0) > 0)
                                        <span class="inline-flex items-center justify-center px-2 py-0.5 text-xs font-bold rounded-full bg-red-100 text-red-700">
                                            {{ $sidebarIncidentCount > 99 ? '99+' : $sidebarIncidentCount }}
                                        </span>
                                    @endif
                                </a>
                            @endif
                            
                            <a href="{{ route('delivery-monitoring.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('delivery-monitoring.*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="mail" class="mr-3 h-5 w-5 {{ request()->routeIs('delivery-monitoring.*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                Delivery
                            </a>
                            
                            <a href="{{ route('dmarc.index') }}" 
                               class="group flex items-center px-2 py-2 text-sm font-medium rounded-md {{ request()->routeIs('dmarc.*') ? 'bg-blue-100 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900' }}">
                                <i data-lucide="file-bar-chart" class="mr-3 h-5 w-5 {{ request()->routeIs('dmarc.*') ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500' }}"></i>
                                DMARC Activity
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
                                @click="sidebarOpen = true">
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

        <!-- Help Widget -->
        <div x-data="{ 
            helpOpen: false, 
            helpMessage: '', 
            helpSending: false, 
            helpSent: false,
            helpError: '',
            async sendHelp() {
                if (!this.helpMessage.trim() || this.helpMessage.length < 10) {
                    this.helpError = 'Please enter at least 10 characters';
                    return;
                }
                this.helpSending = true;
                this.helpError = '';
                try {
                    const response = await fetch('{{ route('support.send') }}', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-TOKEN': document.querySelector('meta[name=csrf-token]').content
                        },
                        body: JSON.stringify({ message: this.helpMessage })
                    });
                    const data = await response.json();
                    if (data.success) {
                        this.helpSent = true;
                        this.helpMessage = '';
                        setTimeout(() => { this.helpSent = false; this.helpOpen = false; }, 2000);
                    } else {
                        this.helpError = data.message || 'Failed to send message';
                    }
                } catch (e) {
                    this.helpError = 'Failed to send message. Please try again.';
                }
                this.helpSending = false;
            }
        }" class="fixed bottom-6 right-6 z-50">
            <!-- Help Button -->
            <button @click="helpOpen = !helpOpen; helpSent = false; helpError = ''"
                    class="flex items-center justify-center w-14 h-14 bg-blue-600 hover:bg-blue-700 text-white rounded-full shadow-lg transition-all duration-200 hover:scale-105"
                    :class="{ 'rotate-45': helpOpen }">
                <i x-show="!helpOpen" data-lucide="help-circle" class="h-6 w-6"></i>
                <i x-show="helpOpen" data-lucide="x" class="h-6 w-6"></i>
            </button>
            
            <!-- Help Panel -->
            <div x-show="helpOpen"
                 x-transition:enter="transition ease-out duration-200"
                 x-transition:enter-start="opacity-0 translate-y-4"
                 x-transition:enter-end="opacity-100 translate-y-0"
                 x-transition:leave="transition ease-in duration-150"
                 x-transition:leave-start="opacity-100 translate-y-0"
                 x-transition:leave-end="opacity-0 translate-y-4"
                 class="absolute bottom-16 right-0 w-80 bg-white rounded-lg shadow-xl border border-gray-200 overflow-hidden">
                <div class="bg-blue-600 px-4 py-3">
                    <h3 class="text-white font-semibold flex items-center">
                        <i data-lucide="message-circle" class="h-5 w-5 mr-2"></i>
                        Need Help?
                    </h3>
                    <p class="text-blue-100 text-sm mt-1">Send us a message and we'll get back to you.</p>
                </div>
                
                <div class="p-4">
                    <template x-if="helpSent">
                        <div class="text-center py-4">
                            <i data-lucide="check-circle" class="h-12 w-12 text-green-500 mx-auto mb-2"></i>
                            <p class="text-green-600 font-medium">Message sent!</p>
                            <p class="text-gray-500 text-sm">We'll reply to your email soon.</p>
                        </div>
                    </template>
                    
                    <template x-if="!helpSent">
                        <div>
                            <textarea x-model="helpMessage"
                                      @keydown.enter.ctrl="sendHelp()"
                                      @keydown.enter.meta="sendHelp()"
                                      placeholder="Describe your question or issue..."
                                      rows="4"
                                      class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none text-sm"
                                      :disabled="helpSending"></textarea>
                            
                            <p x-show="helpError" x-text="helpError" class="text-red-500 text-xs mt-1"></p>
                            
                            <div class="mt-3 flex items-center justify-between">
                                <span class="text-xs text-gray-400">Ctrl+Enter to send</span>
                                <button @click="sendHelp()"
                                        :disabled="helpSending || helpMessage.length < 10"
                                        class="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center">
                                    <span x-show="!helpSending">Send</span>
                                    <span x-show="helpSending" class="flex items-center">
                                        <svg class="animate-spin h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24">
                                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                        </svg>
                                        Sending...
                                    </span>
                                </button>
                            </div>
                        </div>
                    </template>
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
