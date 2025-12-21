<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\BlacklistApiController;
use App\Http\Controllers\StripeWebhookController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

// Stripe webhook (no CSRF protection in API routes)
Route::post('/stripe/webhook', [StripeWebhookController::class, 'handle'])
    ->name('stripe.webhook');

// Blacklist API Routes
Route::middleware('auth:sanctum')->prefix('blacklist')->group(function () {
    Route::get('/statistics', [BlacklistApiController::class, 'statistics']);
    Route::get('/domains/{domain}/status', [BlacklistApiController::class, 'status']);
    Route::get('/domains/{domain}/history', [BlacklistApiController::class, 'history']);
    Route::post('/domains/{domain}/check', [BlacklistApiController::class, 'check']);
});

// SPF API Routes
Route::middleware('auth:sanctum')->prefix('spf')->group(function () {
    Route::post('/run', [App\Http\Controllers\SpfController::class, 'run']);
    Route::get('/history', [App\Http\Controllers\SpfController::class, 'history']);
});
