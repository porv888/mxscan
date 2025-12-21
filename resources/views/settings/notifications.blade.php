@extends('layouts.app')

@section('title', 'Notification Settings')

@section('content')
<div class="max-w-4xl mx-auto py-6 sm:px-6 lg:px-8">
    <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg">
        <div class="p-6 bg-white border-b border-gray-200">
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-gray-900">Notification Settings</h2>
                    <p class="mt-1 text-sm text-gray-600">Manage how you receive alerts and reports from MXScan.</p>
                </div>
            </div>

            <form method="POST" action="{{ route('settings.notifications.update') }}" class="space-y-6">
                @csrf
                @method('PUT')

                <!-- Email Notifications -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <div class="flex items-start">
                        <div class="flex items-center h-5">
                            <input id="email_enabled" name="email_enabled" type="checkbox" 
                                   class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded"
                                   {{ $prefs->email_enabled ? 'checked' : '' }} value="1">
                        </div>
                        <div class="ml-3 text-sm">
                            <label for="email_enabled" class="font-medium text-gray-700">
                                📧 Email Notifications
                            </label>
                            <p class="text-gray-500">Receive security alerts and incident notifications via email.</p>
                        </div>
                    </div>
                </div>

                <!-- Slack Notifications -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <div class="flex items-start">
                        <div class="flex items-center h-5">
                            <input id="slack_enabled" name="slack_enabled" type="checkbox" 
                                   class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded"
                                   {{ $prefs->slack_enabled ? 'checked' : '' }} value="1"
                                   @if(!auth()->user()->canUseSlackNotifications()) disabled @endif>
                        </div>
                        <div class="ml-3 text-sm flex-1">
                            <label for="slack_enabled" class="font-medium text-gray-700 flex items-center">
                                💬 Slack Notifications
                                @if(!auth()->user()->canUseSlackNotifications())
                                    <span class="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                        🔒 Premium Feature
                                    </span>
                                @endif
                            </label>
                            <p class="text-gray-500 mb-3">Send alerts to your Slack workspace via webhook.</p>
                            
                            @if(auth()->user()->canUseSlackNotifications())
                                <div class="mt-2">
                                    <label for="slack_webhook" class="block text-sm font-medium text-gray-700">Slack Webhook URL</label>
                                    <input type="url" name="slack_webhook" id="slack_webhook" 
                                           class="mt-1 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md"
                                           placeholder="https://hooks.slack.com/services/..."
                                           value="{{ $prefs->slack_webhook }}">
                                    <p class="mt-1 text-xs text-gray-500">
                                        <a href="https://api.slack.com/messaging/webhooks" target="_blank" class="text-blue-600 hover:text-blue-500">
                                            Learn how to create a Slack webhook →
                                        </a>
                                    </p>
                                </div>
                            @else
                                <div class="mt-2 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
                                    <p class="text-sm text-yellow-700">
                                        Slack notifications are available with Premium and Ultra plans.
                                        <a href="{{ route('pricing') }}" class="font-medium underline">Upgrade now</a>
                                    </p>
                                </div>
                            @endif
                        </div>
                    </div>
                </div>

                <!-- Weekly Reports -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <div class="flex items-start">
                        <div class="flex items-center h-5">
                            <input id="weekly_reports" name="weekly_reports" type="checkbox" 
                                   class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded"
                                   {{ $prefs->weekly_reports ? 'checked' : '' }} value="1"
                                   @if(!auth()->user()->canUseWeeklyReports()) disabled @endif>
                        </div>
                        <div class="ml-3 text-sm">
                            <label for="weekly_reports" class="font-medium text-gray-700 flex items-center">
                                📊 Weekly Reports
                                @if(!auth()->user()->canUseWeeklyReports())
                                    <span class="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                        🔒 Premium Feature
                                    </span>
                                @endif
                            </label>
                            <p class="text-gray-500">Receive comprehensive weekly PDF reports every Monday.</p>
                            
                            @if(!auth()->user()->canUseWeeklyReports())
                                <div class="mt-2 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
                                    <p class="text-sm text-yellow-700">
                                        Weekly reports are available with Premium and Ultra plans.
                                        <a href="{{ route('pricing') }}" class="font-medium underline">Upgrade now</a>
                                    </p>
                                </div>
                            @endif
                        </div>
                    </div>
                </div>

                <!-- Current Plan Info -->
                <div class="bg-blue-50 p-4 rounded-lg">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-medium text-blue-800">Current Plan: {{ ucfirst(auth()->user()->currentPlanKey()) }}</h3>
                            <div class="mt-2 text-sm text-blue-700">
                                <p>Your current plan includes:</p>
                                <ul class="list-disc list-inside mt-1 space-y-1">
                                    <li>Email notifications ✅</li>
                                    <li>Slack notifications {{ auth()->user()->canUseSlackNotifications() ? '✅' : '❌' }}</li>
                                    <li>Weekly reports {{ auth()->user()->canUseWeeklyReports() ? '✅' : '❌' }}</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Save Button -->
                <div class="flex justify-end">
                    <button type="submit" 
                            class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                        Save Preferences
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection
