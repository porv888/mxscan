<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Auth\Notifications\VerifyEmail;
use App\Notifications\VerifyEmailBranded;
use Laravel\Cashier\Cashier;
use App\Models\CashierSubscription;
use App\Observers\CashierSubscriptionObserver;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Use our branded email verification notification
        VerifyEmail::toMailUsing(function ($notifiable, $url) {
            return (new VerifyEmailBranded)->toMail($notifiable);
        });

        // Configure Cashier to use our custom Subscription model with app_subscriptions table
        Cashier::useSubscriptionModel(CashierSubscription::class);

        // Register Cashier Subscription observer to automatically set plan_id
        CashierSubscription::observe(CashierSubscriptionObserver::class);
    }
}
