<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Billing\PlanController;
use App\Http\Controllers\BillingController;
use App\Http\Controllers\StripeWebhookController;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;

Route::get('/', function () {
    if (auth()->check()) {
        return redirect()->route('dashboard');
    }
    return redirect()->route('login');
});

// Public routes
Route::get('/pricing', [PlanController::class, 'pricing'])->name('pricing');

// Notification email verification (public route)
Route::get('/notification-email/verify/{token}', [App\Http\Controllers\NotificationEmailController::class, 'verify'])->name('notification-emails.verify');

// Authentication Routes
Auth::routes(['verify' => false]); // Disable built-in verification routes

// Custom Email Verification Routes
Route::middleware('auth')->group(function () {
    // Verification notice page
    Route::get('/email/verify', function () {
        return view('auth.verify');
    })->name('verification.notice');

    // Email verification link callback
    Route::get('/email/verify/{id}/{hash}', function (EmailVerificationRequest $request) {
        $request->fulfill();
        return redirect()->route('dashboard')->with('status', 'Email verified. Welcome to MXScan!');
    })->middleware('signed')->name('verification.verify');

    // Resend verification link
    Route::post('/email/resend', function (Request $request) {
        if ($request->user()->hasVerifiedEmail()) {
            return redirect()->intended(route('dashboard'));
        }
        $request->user()->sendEmailVerificationNotification();
        return back()->with('resent', true);
    })->middleware('throttle:6,1')->name('verification.resend');
});

// Post-login redirect handler
Route::middleware('auth')->get('/post-login', function (Request $request) {
    return $request->user()->hasVerifiedEmail()
        ? redirect()->route('dashboard')
        : redirect()->route('verification.notice');
})->name('post-login.redirect');

// Dashboard routes (protected by auth + verified middleware)
Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [App\Http\Controllers\DashboardController::class, 'index'])->name('dashboard');

    // Domain Management Routes (new simplified routes)
    Route::get('/domains', [App\Http\Controllers\DomainController::class, 'index'])->name('domains');
    Route::resource('/dashboard/domains', App\Http\Controllers\DomainController::class, [
        'names' => [
            'index' => 'dashboard.domains',
            'create' => 'dashboard.domains.create',
            'store' => 'dashboard.domains.store',
            'edit' => 'dashboard.domains.edit',
            'update' => 'dashboard.domains.update',
            'destroy' => 'dashboard.domains.destroy'
        ],
        'parameters' => ['domains' => 'domain']
    ]);

    // Automation Routes (replaces Schedules)
    Route::get('/automations', [App\Http\Controllers\AutomationController::class, 'index'])->name('automations.index');
    Route::get('/automations/create', [App\Http\Controllers\AutomationController::class, 'create'])->name('automations.create');
    Route::post('/automations', [App\Http\Controllers\AutomationController::class, 'store'])->name('automations.store');
    Route::get('/automations/{schedule}/edit', [App\Http\Controllers\AutomationController::class, 'edit'])->name('automations.edit');
    Route::put('/automations/{schedule}', [App\Http\Controllers\AutomationController::class, 'update'])->name('automations.update');
    Route::post('/automations/{schedule}/run-now', [App\Http\Controllers\AutomationController::class, 'runNow'])->name('automations.run-now');
    Route::post('/automations/{schedule}/pause', [App\Http\Controllers\AutomationController::class, 'pause'])->name('automations.pause');
    Route::post('/automations/{schedule}/resume', [App\Http\Controllers\AutomationController::class, 'resume'])->name('automations.resume');
    Route::delete('/automations/{schedule}', [App\Http\Controllers\AutomationController::class, 'destroy'])->name('automations.destroy');

    // Report Routes (replaces Scans)
    Route::get('/reports', [App\Http\Controllers\ReportController::class, 'index'])->name('reports.index');
    Route::get('/reports/export', [App\Http\Controllers\ReportController::class, 'export'])->name('reports.export');
    Route::get('/reports/{scan}', [App\Http\Controllers\ReportController::class, 'show'])->name('reports.show');

    // Legacy Scan Routes (for backward compatibility)
    Route::get('/dashboard/scans', [App\Http\Controllers\ScanController::class, 'index'])->name('dashboard.scans');
    Route::post('/dashboard/domains/{domain}/scan', [App\Http\Controllers\ScanController::class, 'start'])->name('scans.start');
    Route::get('/dashboard/scans/{scan}', [App\Http\Controllers\ScanController::class, 'show'])->name('scans.show');
    Route::get('/dashboard/scans/{scan}/status', [App\Http\Controllers\ScanController::class, 'status'])->name('scans.status');
    Route::get('/dashboard/scans/{scan}/result', [App\Http\Controllers\ScanController::class, 'result'])->name('scans.result');
    
    // Blacklist Scan Routes
    Route::post('/dashboard/domains/{domain}/blacklist', [App\Http\Controllers\BlacklistScanController::class, 'run'])->name('blacklist.check');
    Route::get('/dashboard/domains/{domain}/blacklist/status', [App\Http\Controllers\BlacklistScanController::class, 'status'])->name('blacklist.status');
    
    // Domain Schedule Routes
    Route::post('/dashboard/domains/{domain}/schedule', [App\Http\Controllers\DomainController::class, 'schedule'])->name('domains.schedule');
    
    // Domain Settings Routes (for updating services and cadence)
    Route::post('/domains/{domain}/settings/services', [App\Http\Controllers\DomainSettingsController::class, 'updateServices'])->name('domains.settings.services');
    Route::post('/domains/{domain}/settings/cadence', [App\Http\Controllers\DomainSettingsController::class, 'updateCadence'])->name('domains.settings.cadence');
    
    // New Unified Scan Routes (must come before domains/{domain} prefix group to avoid conflicts)
    Route::post('/domains/{domain}/scan', [App\Http\Controllers\ScanController::class, 'run'])->name('domains.scan');
    Route::post('/domains/{domain}/scan/dns', [App\Http\Controllers\ScanController::class, 'runDns'])->name('domains.scan.dns');
    Route::post('/domains/{domain}/scan/blacklist', [App\Http\Controllers\ScanController::class, 'runBlacklist'])->name('domains.scan.blacklist');
    Route::post('/domains/{domain}/scan/spf', [App\Http\Controllers\ScanController::class, 'runSpf'])->name('domains.scan.spf');
    
    // NEW: Synchronous scan endpoint
    Route::post('/domains/{domain}/scan-now', [App\Http\Controllers\ScanController::class, 'runSync'])->name('domains.scan.now');
    
    // Expiry refresh endpoint
    Route::post('/domains/{domain}/expiry/refresh', [App\Http\Controllers\DomainController::class, 'refreshExpiry'])->name('domains.expiry.refresh');
    
    // Domain Details hub (tabs)
    Route::prefix('domains/{domain}')->group(function () {
        Route::get('/', [App\Http\Controllers\DomainHubController::class, 'overview'])->name('domains.hub');
        Route::get('/history', [App\Http\Controllers\DomainHubController::class, 'history'])->name('domains.hub.history');
        Route::get('/schedules', [App\Http\Controllers\DomainHubController::class, 'schedules'])->name('domains.hub.schedules');
        Route::get('/tools', [App\Http\Controllers\DomainHubController::class, 'tools'])->name('domains.hub.tools');
        Route::get('/settings', [App\Http\Controllers\DomainHubController::class, 'settings'])->name('domains.hub.settings');
        
        // Actions (scan moved to unified scan system)
        Route::post('/blacklist', [App\Http\Controllers\DomainActionsController::class, 'runBlacklist'])->name('domains.hub.blacklist');
        Route::get('/fix-pack', [App\Http\Controllers\DomainActionsController::class, 'downloadFixPack'])->name('domains.hub.fixpack');
    });
    
    // SPF Optimizer Routes
    Route::get('/domains/{domain}/spf', [App\Http\Controllers\SpfController::class, 'show'])->name('spf.show');
    Route::post('/domains/{domain}/spf/run', [App\Http\Controllers\SpfController::class, 'run'])->name('spf.run');
    Route::get('/domains/{domain}/spf/history', [App\Http\Controllers\SpfController::class, 'history'])->name('spf.history');
    
    // RBL Delisting Routes
    Route::get('/domains/{domain}/rbl/{provider}/info', [App\Http\Controllers\RblController::class, 'info'])->name('rbl.info');
    Route::get('/domains/{domain}/rbl/evidence', [App\Http\Controllers\RblController::class, 'evidence'])->name('rbl.evidence');
    Route::post('/domains/{domain}/rbl/submitted', [App\Http\Controllers\RblController::class, 'submitted'])->name('rbl.submitted');
    Route::post('/domains/{domain}/rbl/recheck', [App\Http\Controllers\RblController::class, 'recheck'])->name('rbl.recheck');
    
    // Quick tools (post back to same page with flash)
    Route::post('/tools/smtp-test', [App\Http\Controllers\ToolsController::class, 'smtpTest'])->name('tools.smtp');
    Route::post('/tools/bimi-check', [App\Http\Controllers\ToolsController::class, 'bimiCheck'])->name('tools.bimi');
    Route::post('/tools/spf-wizard', [App\Http\Controllers\ToolsController::class, 'spfWizard'])->name('tools.spf');
    
    // Schedule Management Routes
    Route::resource('/dashboard/schedules', App\Http\Controllers\ScheduleController::class, [
        'names' => [
            'index' => 'schedules.index',
            'create' => 'schedules.create',
            'store' => 'schedules.store',
            'edit' => 'schedules.edit',
            'update' => 'schedules.update',
            'destroy' => 'schedules.destroy'
        ]
    ]);
    Route::post('/dashboard/schedules/{schedule}/pause', [App\Http\Controllers\ScheduleController::class, 'pause'])->name('schedules.pause');
    Route::post('/dashboard/schedules/{schedule}/resume', [App\Http\Controllers\ScheduleController::class, 'resume'])->name('schedules.resume');
    Route::post('/dashboard/schedules/{schedule}/run-now', [App\Http\Controllers\ScheduleController::class, 'runNow'])->name('schedules.run-now');

    // Profile routes
    Route::get('/dashboard/profile', [App\Http\Controllers\ProfileController::class, 'edit'])->name('dashboard.profile');
    Route::get('/profile', [App\Http\Controllers\ProfileController::class, 'edit'])->name('profile.show');
    Route::patch('/profile', [App\Http\Controllers\ProfileController::class, 'update'])->name('profile.update');
    Route::put('/profile/password', [App\Http\Controllers\ProfileController::class, 'updatePassword'])->name('profile.password');
    Route::delete('/profile', [App\Http\Controllers\ProfileController::class, 'destroy'])->name('profile.destroy');

    // Notification Email routes
    Route::post('/profile/notification-emails', [App\Http\Controllers\NotificationEmailController::class, 'store'])->name('notification-emails.store');
    Route::delete('/profile/notification-emails/{notificationEmail}', [App\Http\Controllers\NotificationEmailController::class, 'destroy'])->name('notification-emails.destroy');
    Route::post('/profile/notification-emails/{notificationEmail}/resend', [App\Http\Controllers\NotificationEmailController::class, 'resendVerification'])->name('notification-emails.resend');

    // Billing routes (Stripe + Cashier)
    Route::get('/billing', [BillingController::class, 'show'])->name('billing');
    Route::post('/billing/checkout', [BillingController::class, 'checkout'])->name('billing.checkout');
    Route::post('/billing/swap', [BillingController::class, 'swap'])->name('billing.swap');
    Route::post('/billing/portal', [BillingController::class, 'portal'])->name('billing.portal');
    Route::get('/billing/success', [BillingController::class, 'success'])->name('billing.success');
    Route::get('/billing/cancel', [BillingController::class, 'cancel'])->name('billing.cancel');
    
    // Plan management routes
    Route::post('/billing/plan/change', [PlanController::class, 'change'])->name('billing.plan.change');
    
    // Notification settings routes
    Route::get('/settings/notifications', [App\Http\Controllers\NotificationPrefsController::class, 'show'])->name('settings.notifications');
    Route::put('/settings/notifications', [App\Http\Controllers\NotificationPrefsController::class, 'update'])->name('settings.notifications.update');
    
    // User Monitoring Routes (Premium/Ultra only)
    Route::prefix('monitoring')->name('monitoring.')->group(function () {
        Route::get('/incidents', [App\Http\Controllers\MonitoringController::class, 'incidents'])->name('incidents');
        Route::get('/incidents/{incident}', [App\Http\Controllers\MonitoringController::class, 'showIncident'])->name('incidents.show');
        Route::get('/snapshots', [App\Http\Controllers\MonitoringController::class, 'snapshots'])->name('snapshots');
        Route::get('/snapshots/{snapshot}', [App\Http\Controllers\MonitoringController::class, 'showSnapshot'])->name('snapshots.show');
    });
    
    // Delivery Monitoring Routes (new simplified routes)
    Route::get('/delivery', [App\Http\Controllers\DeliveryMonitorController::class, 'index'])->name('delivery');
    Route::prefix('delivery-monitoring')->name('delivery-monitoring.')->group(function () {
        Route::get('/', [App\Http\Controllers\DeliveryMonitorController::class, 'index'])->name('index');
        Route::get('/create', [App\Http\Controllers\DeliveryMonitorController::class, 'create'])->name('create');
        Route::post('/', [App\Http\Controllers\DeliveryMonitorController::class, 'store'])->name('store');
        Route::get('/{monitor}', [App\Http\Controllers\DeliveryMonitorController::class, 'show'])->name('show');
        Route::post('/{monitor}/pause', [App\Http\Controllers\DeliveryMonitorController::class, 'pause'])->name('pause');
        Route::post('/{monitor}/resume', [App\Http\Controllers\DeliveryMonitorController::class, 'resume'])->name('resume');
        Route::delete('/{monitor}', [App\Http\Controllers\DeliveryMonitorController::class, 'destroy'])->name('destroy');
    });
    
    // API endpoint for delivery check details
    Route::get('/api/delivery-checks/{check}', [App\Http\Controllers\DeliveryMonitorController::class, 'getCheckDetails']);

    // DMARC Visibility Routes
    Route::get('/dmarc', [App\Http\Controllers\DmarcController::class, 'index'])->name('dmarc.index');
    Route::prefix('domains/{domain}/dmarc')->name('dmarc.')->group(function () {
        Route::get('/', [App\Http\Controllers\DmarcController::class, 'show'])->name('show');
        Route::post('/check-dns', [App\Http\Controllers\DmarcController::class, 'checkDns'])->name('check-dns');
        Route::post('/upload', [App\Http\Controllers\DmarcController::class, 'upload'])->name('upload');
        Route::put('/alerts', [App\Http\Controllers\DmarcController::class, 'updateAlertSettings'])->name('alerts.update');
        Route::post('/events/{event}/acknowledge', [App\Http\Controllers\DmarcController::class, 'acknowledgeEvent'])->name('events.acknowledge');
        Route::get('/chart-data', [App\Http\Controllers\DmarcController::class, 'chartData'])->name('chart-data');
        Route::get('/senders-data', [App\Http\Controllers\DmarcController::class, 'sendersData'])->name('senders-data');
        Route::get('/senders/{sender}', [App\Http\Controllers\DmarcController::class, 'getSender'])->name('senders.show');
    });

    // Profile routes (new simplified route)
    Route::get('/profile', [App\Http\Controllers\ProfileController::class, 'edit'])->name('profile');
});

Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');

// Admin Routes (protected by auth + admin role)
Route::middleware(['auth', 'verified', 'admin'])->prefix('admin')->name('admin.')->group(function () {
    Route::get('/dashboard', [App\Http\Controllers\Admin\AdminController::class, 'dashboard'])->name('dashboard');
    
    // Users
    Route::get('/users', [App\Http\Controllers\Admin\UsersController::class, 'index'])->name('users.index');
    Route::get('/users/export', [App\Http\Controllers\Admin\UsersController::class, 'export'])->name('users.export');
    Route::get('/users/create', [App\Http\Controllers\Admin\UsersController::class, 'create'])->name('users.create');
    Route::post('/users', [App\Http\Controllers\Admin\UsersController::class, 'store'])->name('users.store');
    Route::get('/users/{user}', [App\Http\Controllers\Admin\UsersController::class, 'show'])->name('users.show');
    Route::get('/users/{user}/edit', [App\Http\Controllers\Admin\UsersController::class, 'edit'])->name('users.edit');
    Route::patch('/users/{user}', [App\Http\Controllers\Admin\UsersController::class, 'update'])->name('users.update');
    Route::delete('/users/{user}', [App\Http\Controllers\Admin\UsersController::class, 'destroy'])->name('users.destroy');

    // Impersonation
    Route::post('/impersonate/{user}', [App\Http\Controllers\Admin\ImpersonateController::class, 'start'])->name('impersonate.start');
    Route::post('/impersonate/stop', [App\Http\Controllers\Admin\ImpersonateController::class, 'stop'])->name('impersonate.stop');

    // Domains
    Route::get('/domains', [App\Http\Controllers\Admin\AdminDomainsController::class, 'index'])->name('domains.index');
    Route::get('/domains/export', [App\Http\Controllers\Admin\AdminDomainsController::class, 'export'])->name('domains.export');
    Route::get('/domains/{domain}', [App\Http\Controllers\Admin\AdminDomainsController::class, 'show'])->name('domains.show');
    Route::patch('/domains/{domain}', [App\Http\Controllers\Admin\AdminDomainsController::class, 'update'])->name('domains.update');
    Route::post('/domains/{domain}/scan', [App\Http\Controllers\Admin\AdminDomainsController::class, 'runScan'])->name('domains.scan');
    Route::post('/domains/{domain}/blacklist', [App\Http\Controllers\Admin\AdminDomainsController::class, 'runBlacklist'])->name('domains.blacklist');
    Route::post('/domains/{domain}/transfer', [App\Http\Controllers\Admin\AdminDomainsController::class, 'transfer'])->name('domains.transfer');
    Route::delete('/domains/{domain}', [App\Http\Controllers\Admin\AdminDomainsController::class, 'destroy'])->name('domains.destroy');

    // Subscriptions
    Route::get('/subscriptions', [App\Http\Controllers\Admin\AdminSubscriptionController::class, 'index'])->name('subscriptions.index');
    Route::get('/subscriptions/export', [App\Http\Controllers\Admin\AdminSubscriptionController::class, 'export'])->name('subscriptions.export');
    Route::get('/subscriptions/{subscription}', [App\Http\Controllers\Admin\AdminSubscriptionController::class, 'show'])->name('subscriptions.show');
    Route::put('/subscriptions/{subscription}', [App\Http\Controllers\Admin\AdminSubscriptionController::class, 'update'])->name('subscriptions.update');
    Route::post('/subscriptions/{subscription}/cancel', [App\Http\Controllers\Admin\AdminSubscriptionController::class, 'cancel'])->name('subscriptions.cancel');
    Route::post('/subscriptions/{subscription}/resume', [App\Http\Controllers\Admin\AdminSubscriptionController::class, 'resume'])->name('subscriptions.resume');
    
    // Monitoring Admin Routes - TODO: Create these controllers
    // Route::get('/incidents', [App\Http\Controllers\Admin\AdminIncidentsController::class, 'index'])->name('incidents.index');
    // Route::get('/incidents/{incident}', [App\Http\Controllers\Admin\AdminIncidentsController::class, 'show'])->name('incidents.show');
    // Route::patch('/incidents/{incident}', [App\Http\Controllers\Admin\AdminIncidentsController::class, 'update'])->name('incidents.update');
    // Route::delete('/incidents/{incident}', [App\Http\Controllers\Admin\AdminIncidentsController::class, 'destroy'])->name('incidents.destroy');
    
    // Route::get('/snapshots', [App\Http\Controllers\Admin\AdminSnapshotsController::class, 'index'])->name('snapshots.index');
    // Route::get('/snapshots/{snapshot}', [App\Http\Controllers\Admin\AdminSnapshotsController::class, 'show'])->name('snapshots.show');
    // Route::delete('/snapshots/{snapshot}', [App\Http\Controllers\Admin\AdminSnapshotsController::class, 'destroy'])->name('snapshots.destroy');
    
    // Route::get('/notifications', [App\Http\Controllers\Admin\AdminNotificationsController::class, 'index'])->name('notifications.index');
    // Route::get('/notifications/test', [App\Http\Controllers\Admin\AdminNotificationsController::class, 'test'])->name('notifications.test');
    // Route::post('/notifications/send-test', [App\Http\Controllers\Admin\AdminNotificationsController::class, 'sendTest'])->name('notifications.send-test');
    
    // Placeholder routes for other admin sections (to be implemented later)
    Route::get('/scans', function() { return 'Scans management - coming soon'; })->name('scans.index');
    Route::get('/plans', function() { return 'Plans management - coming soon'; })->name('plans.index');
    Route::get('/plans/create', function() { return 'Create plan - coming soon'; })->name('plans.create');
    Route::get('/invoices', function() { return 'Invoices management - coming soon'; })->name('invoices.index');
    Route::get('/audit', function() { return 'Audit logs - coming soon'; })->name('audit.index');
    Route::get('/settings', function() { return 'Settings - coming soon'; })->name('settings.index');
});

// Stripe webhook moved to api.php for better CSRF handling
