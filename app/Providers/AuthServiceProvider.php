<?php

namespace App\Providers;

use App\Models\Domain;
use App\Models\DeliveryMonitor;
use App\Policies\DomainPolicy;
use App\Policies\DeliveryMonitorPolicy;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The model to policy mappings for the application.
     *
     * @var array<class-string, class-string>
     */
    protected $policies = [
        Domain::class => DomainPolicy::class,
        DeliveryMonitor::class => DeliveryMonitorPolicy::class,
    ];

    /**
     * Register any authentication / authorization services.
     */
    public function boot(): void
    {
        //
    }
}
