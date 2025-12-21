<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ config('app.name', 'Laravel') }} - Reset Password</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div>
                <div class="mx-auto h-12 w-12 flex items-center justify-center bg-green-600 rounded-lg">
                    <i data-lucide="shield-check" class="h-8 w-8 text-white"></i>
                </div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
                    Set new password
                </h2>
                <p class="mt-2 text-center text-sm text-gray-600">
                    Enter your new password below
                </p>
            </div>
            
            <div class="bg-white shadow rounded-lg p-6">
                <form method="POST" action="{{ route('password.update') }}">
                    @csrf
                    <input type="hidden" name="token" value="{{ $token }}">
                    
                    <div class="space-y-4">
                        <div>
                            <label for="email" class="block text-sm font-medium text-gray-700">Email Address</label>
                            <input id="email" name="email" type="email" autocomplete="email" required 
                                   value="{{ $email ?? old('email') }}" autofocus
                                   class="mt-1 appearance-none relative block w-full px-3 py-2 border @error('email') border-red-300 @else border-gray-300 @enderror placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm" 
                                   placeholder="Enter your email address">
                            @error('email')
                                <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                            @enderror
                        </div>
                        
                        <div>
                            <label for="password" class="block text-sm font-medium text-gray-700">New Password</label>
                            <input id="password" name="password" type="password" autocomplete="new-password" required 
                                   class="mt-1 appearance-none relative block w-full px-3 py-2 border @error('password') border-red-300 @else border-gray-300 @enderror placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm" 
                                   placeholder="Enter new password">
                            @error('password')
                                <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                            @enderror
                        </div>
                        
                        <div>
                            <label for="password-confirm" class="block text-sm font-medium text-gray-700">Confirm New Password</label>
                            <input id="password-confirm" name="password_confirmation" type="password" autocomplete="new-password" required 
                                   class="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm" 
                                   placeholder="Confirm new password">
                        </div>
                    </div>

                    <div class="mt-6">
                        <button type="submit" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
                            <i data-lucide="check" class="h-4 w-4 mr-2"></i>
                            Reset Password
                        </button>
                    </div>
                </form>
                
                <div class="mt-4 text-center">
                    <a href="{{ route('login') }}" class="text-sm text-blue-600 hover:text-blue-500">
                        ← Back to login
                    </a>
                </div>
            </div>
        </div>
    </div>

    <script>
        lucide.createIcons();
    </script>
</body>
</html>
