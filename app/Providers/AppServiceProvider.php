<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\View;
use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\Notifications\VerifyEmail;
use App\Notifications\VerifyEmailBranded;
use App\Services\Entitlement\EntitlementFeature;
use App\Services\Entitlement\EntitlementService;
use Laravel\Cashier\Cashier;
use App\Models\CashierSubscription;
use App\Models\Incident;
use App\Observers\CashierSubscriptionObserver;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->singleton(EntitlementService::class);
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

        // Share incident count with layout for sidebar badge
        View::composer('layouts.app', function ($view) {
            $sidebarIncidentCount = 0;
            $entitlementFlags = [
                'entitlementAutomations' => false,
                'entitlementDelivery' => false,
                'entitlementDmarc' => false,
                'entitlementTools' => false,
                'entitlementMonitoring' => false,
            ];

            if (Auth::check()) {
                $user = Auth::user();
                $entitlements = app(EntitlementService::class);
                $domainIds = $user->domains()->pluck('id');
                $sidebarIncidentCount = Incident::whereIn('domain_id', $domainIds)
                    ->unresolved()
                    ->count();

                $entitlementFlags = [
                    'entitlementAutomations' => $entitlements->can($user, EntitlementFeature::AUTOMATIONS),
                    'entitlementDelivery' => $entitlements->can($user, EntitlementFeature::DELIVERY_MONITORING),
                    'entitlementDmarc' => $entitlements->can($user, EntitlementFeature::DMARC_ACTIVITY),
                    'entitlementTools' => $entitlements->can($user, EntitlementFeature::STANDALONE_TOOLS),
                    'entitlementMonitoring' => $entitlements->can($user, EntitlementFeature::MONITORING),
                ];
            }

            $view->with('sidebarIncidentCount', $sidebarIncidentCount);
            $view->with($entitlementFlags);
        });
    }
}
