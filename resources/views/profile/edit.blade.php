@extends('layouts.app')

@section('title', 'Profile Settings')

@section('content')
<div class="max-w-4xl mx-auto space-y-6">
    <!-- Success Message -->
    @if (session('success'))
        <div class="bg-green-50 border border-green-200 text-green-800 rounded-lg p-4 flex items-center">
            <i data-lucide="check-circle" class="w-5 h-5 mr-3 flex-shrink-0"></i>
            <p>{{ session('success') }}</p>
        </div>
    @endif

    <!-- Header -->
    <div>
        <h1 class="text-2xl font-bold text-gray-900">Profile Settings</h1>
        <p class="text-gray-600 mt-1">Manage your account information and security settings</p>
    </div>

    <!-- Profile Information -->
    <div class="bg-white shadow-sm rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-lg font-semibold text-gray-900">Profile Information</h2>
            <p class="text-sm text-gray-600 mt-1">Update your account's profile information and email address.</p>
        </div>
        
        <form method="POST" action="{{ route('profile.update') }}" class="p-6 space-y-6">
            @csrf
            @method('PATCH')
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Name -->
                <div>
                    <label for="name" class="block text-sm font-medium text-gray-700">Name</label>
                    <input type="text" 
                           name="name" 
                           id="name" 
                           value="{{ old('name', Auth::user()->name) }}"
                           class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm @error('name') border-red-300 @enderror"
                           required>
                    @error('name')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>

                <!-- Email -->
                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700">Email Address</label>
                    <input type="email" 
                           name="email" 
                           id="email" 
                           value="{{ Auth::user()->email }}"
                           class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm @error('email') border-red-300 @enderror"
                           required>
                    @error('email')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>
            </div>

            <!-- Account Status -->
            <div class="bg-gray-50 rounded-lg p-4">
                <div class="flex items-center justify-between">
                    <div>
                        <h3 class="text-lg font-medium text-gray-900">{{ Auth::user()->name }}</h3>
                        <p class="text-sm text-gray-500">{{ Auth::user()->email }}</p>
                        <p class="text-sm text-gray-600">Your account is currently active</p>
                    </div>
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        <i data-lucide="check-circle" class="w-3 h-3 mr-1"></i>
                        Active
                    </span>
                </div>
            </div>

            <div class="flex justify-end">
                <button type="submit" 
                        class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <i data-lucide="save" class="w-4 h-4 mr-2"></i>
                    Save Changes
                </button>
            </div>
        </form>
    </div>

    <!-- Notification Emails -->
    <div class="bg-white shadow-sm rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-lg font-semibold text-gray-900">Notification Emails</h2>
            <p class="text-sm text-gray-600 mt-1">Add additional email addresses to receive alerts, expiry reminders, and incident notifications. Perfect for teams!</p>
        </div>
        
        <div class="p-6 space-y-6">
            <!-- Primary Email Info -->
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div class="flex items-start">
                    <i data-lucide="info" class="w-5 h-5 text-blue-600 mr-3 mt-0.5 flex-shrink-0"></i>
                    <div>
                        <p class="text-sm text-blue-800 font-medium">Your primary email ({{ Auth::user()->email }}) always receives notifications.</p>
                        <p class="text-sm text-blue-700 mt-1">Add additional emails below for team members or backup contacts.</p>
                    </div>
                </div>
            </div>

            <!-- Add New Email Form -->
            <form method="POST" action="{{ route('notification-emails.store') }}" class="space-y-4">
                @csrf
                <div>
                    <label for="notification_email" class="block text-sm font-medium text-gray-700">Add Notification Email</label>
                    <div class="mt-1 flex gap-3">
                        <input type="email" 
                               name="email" 
                               id="notification_email" 
                               placeholder="colleague@company.com"
                               class="flex-1 border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm @error('email') border-red-300 @enderror"
                               required>
                        <button type="submit" 
                                class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                            <i data-lucide="plus" class="w-4 h-4 mr-2"></i>
                            Add Email
                        </button>
                    </div>
                    @error('email')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>
            </form>

            <!-- List of Notification Emails -->
            @php
                $notificationEmails = Auth::user()->notificationEmails;
            @endphp

            @if($notificationEmails->count() > 0)
                <div>
                    <h3 class="text-sm font-medium text-gray-900 mb-3">Additional Notification Recipients ({{ $notificationEmails->count() }})</h3>
                    <div class="space-y-2">
                        @foreach($notificationEmails as $notifEmail)
                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200">
                                <div class="flex items-center flex-1">
                                    <i data-lucide="mail" class="w-4 h-4 text-gray-500 mr-3"></i>
                                    <div class="flex-1">
                                        <p class="text-sm font-medium text-gray-900">{{ $notifEmail->email }}</p>
                                        @if($notifEmail->is_verified)
                                            <p class="text-xs text-green-600 flex items-center mt-0.5">
                                                <i data-lucide="check-circle" class="w-3 h-3 mr-1"></i>
                                                Verified {{ $notifEmail->verified_at->diffForHumans() }}
                                            </p>
                                        @else
                                            <p class="text-xs text-yellow-600 flex items-center mt-0.5">
                                                <i data-lucide="alert-circle" class="w-3 h-3 mr-1"></i>
                                                Pending verification
                                            </p>
                                        @endif
                                    </div>
                                </div>
                                <div class="flex items-center gap-2">
                                    @if(!$notifEmail->is_verified)
                                        <form method="POST" action="{{ route('notification-emails.resend', $notifEmail) }}" class="inline">
                                            @csrf
                                            <button type="submit" 
                                                    class="text-xs text-blue-600 hover:text-blue-800 font-medium">
                                                Resend
                                            </button>
                                        </form>
                                    @endif
                                    <form method="POST" action="{{ route('notification-emails.destroy', $notifEmail) }}" class="inline">
                                        @csrf
                                        @method('DELETE')
                                        <button type="submit" 
                                                onclick="return confirm('Remove this notification email?')"
                                                class="text-red-600 hover:text-red-800">
                                            <i data-lucide="trash-2" class="w-4 h-4"></i>
                                        </button>
                                    </form>
                                </div>
                            </div>
                        @endforeach
                    </div>
                </div>
            @else
                <div class="text-center py-6 bg-gray-50 rounded-lg border border-gray-200">
                    <i data-lucide="mail" class="w-12 h-12 text-gray-400 mx-auto mb-3"></i>
                    <p class="text-sm text-gray-600">No additional notification emails added yet.</p>
                    <p class="text-xs text-gray-500 mt-1">Add team members or backup contacts to receive notifications.</p>
                </div>
            @endif

            <!-- What Gets Sent Info -->
            <div class="bg-gray-50 rounded-lg p-4 border border-gray-200">
                <h4 class="text-sm font-medium text-gray-900 mb-2">What notifications are sent?</h4>
                <ul class="text-sm text-gray-600 space-y-1">
                    <li class="flex items-start">
                        <i data-lucide="check" class="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0"></i>
                        <span>Domain expiry reminders (30, 14, 7 days before)</span>
                    </li>
                    <li class="flex items-start">
                        <i data-lucide="check" class="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0"></i>
                        <span>SSL certificate expiry warnings</span>
                    </li>
                    <li class="flex items-start">
                        <i data-lucide="check" class="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0"></i>
                        <span>Security incidents and blacklist alerts</span>
                    </li>
                    <li class="flex items-start">
                        <i data-lucide="check" class="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0"></i>
                        <span>SPF record changes and warnings</span>
                    </li>
                    <li class="flex items-start">
                        <i data-lucide="check" class="w-4 h-4 text-green-600 mr-2 mt-0.5 flex-shrink-0"></i>
                        <span>Delivery monitoring alerts</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>

    <!-- Subscription / Plan -->
    <div class="bg-white shadow-sm rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-lg font-semibold text-gray-900">Subscription</h2>
            <p class="text-sm text-gray-600 mt-1">Manage your plan and domain limits</p>
        </div>
        
        @php
            $plan = auth()->user()->currentPlan();
            $used = auth()->user()->domainsUsed();
            $limit = auth()->user()->domainLimit();
            $pct = min(100, intval($used / max(1,$limit) * 100));
        @endphp

        <div class="p-6">
            <div class="grid md:grid-cols-3 gap-6">
                <div class="md:col-span-2">
                    <div class="text-gray-500 text-sm">Current Plan</div>
                    <div class="text-lg font-medium">
                        {{ $plan ? $plan->name : 'Freemium' }}
                        @if(!$plan || $plan->price == 0)
                            <span class="ml-2 text-xs px-2 py-1 rounded bg-gray-100">Free</span>
                        @else
                            <span class="ml-2 text-xs px-2 py-1 rounded bg-blue-100 text-blue-800">€{{ number_format($plan->price, 2) }}/mo</span>
                        @endif
                    </div>

                    <div class="mt-4">
                        <div class="flex items-center justify-between text-sm text-gray-600">
                            <div>Domains used</div>
                            <div>{{ $used }} / {{ $limit }}</div>
                        </div>
                        <div class="w-full bg-gray-200 rounded h-2 mt-1">
                            <div class="h-2 rounded {{ $pct>=100 ? 'bg-red-500' : 'bg-blue-600' }}" style="width: {{ $pct }}%"></div>
                        </div>
                        @if($pct>=100)
                            <div class="text-xs text-red-600 mt-2">You've reached your plan limit. Upgrade to add more domains.</div>
                        @endif
                    </div>
                </div>

                <div>
                    <div class="text-gray-500 text-sm mb-2">Manage Plan</div>
                    <a href="{{ route('billing') }}" class="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        <i data-lucide="credit-card" class="w-4 h-4 mr-2"></i>
                        Manage plan
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Update Password -->
    <div class="bg-white shadow-sm rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-lg font-semibold text-gray-900">Update Password</h2>
            <p class="text-sm text-gray-600 mt-1">Ensure your account is using a long, random password to stay secure.</p>
        </div>
        
        <form method="POST" action="{{ route('profile.password') }}" class="p-6 space-y-6">
            @csrf
            @method('PUT')
            
            <div class="space-y-6">
                <!-- Current Password -->
                <div>
                    <label for="current_password" class="block text-sm font-medium text-gray-700">Current Password</label>
                    <input type="password" 
                           name="current_password" 
                           id="current_password" 
                           class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm @error('current_password') border-red-300 @enderror"
                           required>
                    @error('current_password')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>

                <!-- New Password -->
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">New Password</label>
                    <input type="password" 
                           name="password" 
                           id="password" 
                           class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm @error('password') border-red-300 @enderror"
                           required>
                    @error('password')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>

                <!-- Confirm Password -->
                <div>
                    <label for="password_confirmation" class="block text-sm font-medium text-gray-700">Confirm Password</label>
                    <input type="password" 
                           name="password_confirmation" 
                           id="password_confirmation" 
                           class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                           required>
                </div>
            </div>

            <div class="flex justify-end">
                <button type="submit" 
                        class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <i data-lucide="lock" class="w-4 h-4 mr-2"></i>
                    Update Password
                </button>
            </div>
        </form>
    </div>

    <!-- Account Statistics -->
    <div class="bg-white shadow-sm rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-lg font-semibold text-gray-900">Account Statistics</h2>
        </div>
        
        <div class="p-6">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- Member Since -->
                <div class="text-center">
                    <div class="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
                        <i data-lucide="calendar" class="w-6 h-6 text-blue-600"></i>
                    </div>
                    <p class="text-sm text-gray-600">Member Since</p>
                    <p class="text-lg font-semibold text-gray-900">Jan 2024</p>
                </div>

                <!-- Total Domains -->
                <div class="text-center">
                    <div class="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
                        <i data-lucide="globe" class="w-6 h-6 text-green-600"></i>
                    </div>
                    <p class="text-sm text-gray-600">Total Domains</p>
                    <p class="text-lg font-semibold text-gray-900">3</p>
                </div>

                <!-- Total Scans -->
                <div class="text-center">
                    <div class="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-3">
                        <i data-lucide="search" class="w-6 h-6 text-purple-600"></i>
                    </div>
                    <p class="text-sm text-gray-600">Total Scans</p>
                    <p class="text-lg font-semibold text-gray-900">12</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Danger Zone -->
    <div class="bg-white shadow-sm rounded-lg border border-red-200">
        <div class="px-6 py-4 border-b border-red-200 bg-red-50">
            <h2 class="text-lg font-semibold text-red-900">Danger Zone</h2>
            <p class="text-sm text-red-700 mt-1">Irreversible and destructive actions.</p>
        </div>
        
        <div class="p-6">
            <div class="flex items-center justify-between">
                <div>
                    <h3 class="text-sm font-medium text-gray-900">Delete Account</h3>
                    <p class="text-sm text-gray-600 mt-1">
                        Once you delete your account, all of your domains, scans, and data will be permanently deleted. 
                        This action cannot be undone.
                    </p>
                </div>
                <button type="button" onclick="confirmDeleteAccount()" 
                        class="inline-flex items-center px-4 py-2 border border-red-300 text-sm font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    <i data-lucide="trash-2" class="w-4 h-4 mr-2"></i>
                    Delete Account
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Delete Account Confirmation Modal -->
<div id="deleteAccountModal" class="fixed inset-0 z-50 hidden overflow-y-auto" x-data="{ show: false }" x-show="show">
    <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <!-- Background overlay -->
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" @click="show = false"></div>
        
        <!-- Modal panel -->
        <div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
            <div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div class="sm:flex sm:items-start">
                    <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                        <i data-lucide="alert-triangle" class="w-6 h-6 text-red-600"></i>
                    </div>
                    <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                        <h3 class="text-lg leading-6 font-medium text-gray-900">
                            Delete Account
                        </h3>
                        <div class="mt-2">
                            <p class="text-sm text-gray-500">
                                Are you sure you want to delete your account? This action cannot be undone and will permanently delete:
                            </p>
                            <ul class="mt-2 text-sm text-gray-500 list-disc list-inside">
                                <li>All your domains and their configurations</li>
                                <li>All scan results and history</li>
                                <li>Your profile and account data</li>
                            </ul>
                            <div class="mt-4">
                                <label for="confirmDeletePassword" class="block text-sm font-medium text-gray-700">
                                    Enter your password to confirm:
                                </label>
                                <input type="password" 
                                       id="confirmDeletePassword" 
                                       class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-red-500 focus:border-red-500 sm:text-sm"
                                       placeholder="Your password">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <form method="POST" action="{{ route('profile.destroy') }}" id="deleteAccountForm">
                    @csrf
                    @method('DELETE')
                    <input type="hidden" name="password" id="deletePassword">
                    <button type="submit"
                            id="confirmDeleteBtn"
                            disabled
                            class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed">
                        Delete Account
                    </button>
                </form>
                <button type="button" 
                        @click="show = false"
                        class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">
                    Cancel
                </button>
            </div>
        </div>
    </div>
</div>

<script>
    function confirmDeleteAccount() {
        document.getElementById('deleteAccountModal').classList.remove('hidden');
        document.getElementById('deleteAccountModal').__x.$data.show = true;
    }
    
    // Enable delete button only when password is entered
    document.getElementById('confirmDeletePassword').addEventListener('input', function(e) {
        const deleteBtn = document.getElementById('confirmDeleteBtn');
        const passwordInput = document.getElementById('deletePassword');
        
        if (e.target.value.length > 0) {
            deleteBtn.disabled = false;
            passwordInput.value = e.target.value;
        } else {
            deleteBtn.disabled = true;
            passwordInput.value = '';
        }
    });
</script>
@endsection
