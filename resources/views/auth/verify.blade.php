<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ config('app.name', 'MXScan') }} - Verify Email</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div>
                <div class="mx-auto h-12 w-12 flex items-center justify-center bg-blue-600 rounded-lg">
                    <i data-lucide="mail" class="h-8 w-8 text-white"></i>
                </div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
                    Verify your email
                </h2>
                <p class="mt-2 text-center text-sm text-gray-600">
                    We've sent a verification link to <strong>{{ auth()->user()->email }}</strong>
                </p>
            </div>
            
            <div class="bg-white shadow rounded-lg p-6">
                @if (session('resent'))
                    <div class="mb-4 p-4 bg-emerald-50 border border-emerald-200 rounded-md">
                        <div class="flex">
                            <div class="flex-shrink-0">
                                <i data-lucide="check-circle" class="h-5 w-5 text-emerald-400"></i>
                            </div>
                            <div class="ml-3">
                                <p class="text-sm text-emerald-800">
                                    A new verification link has been sent to your email address.
                                </p>
                            </div>
                        </div>
                    </div>
                @endif

                <div class="text-center">
                    <div class="mb-4">
                        <i data-lucide="inbox" class="mx-auto h-12 w-12 text-gray-400"></i>
                    </div>
                    <p class="text-gray-600 mb-6">
                        Please check your inbox (and spam folder). Click the link to continue using MXScan.
                    </p>
                    
                    <div class="flex items-center gap-3 justify-center mb-6">
                        <form method="POST" action="{{ route('verification.resend') }}">
                            @csrf
                            <button type="submit" class="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                <i data-lucide="send" class="h-4 w-4 mr-2 inline"></i>
                                Resend email
                            </button>
                        </form>

                        <form method="POST" action="{{ route('logout') }}">
                            @csrf
                            <button type="submit" class="px-4 py-2 rounded border hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                                Log out
                            </button>
                        </form>
                    </div>

                    <div class="text-sm text-gray-500">
                        Didn't receive it? Wait a minute and try resending. If it still doesn't arrive, contact
                        <a class="underline text-blue-600 hover:text-blue-500" href="mailto:support@mxscan.me">support@mxscan.me</a>.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        lucide.createIcons();
    </script>
</body>
</html>
