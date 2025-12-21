<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('invoices', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->foreignId('subscription_id')->constrained()->onDelete('cascade');
            $table->decimal('amount', 10, 2);
            $table->string('currency', 10)->default('EUR');
            $table->enum('status', ['pending', 'paid', 'failed', 'refunded'])->default('pending');
            $table->string('payment_provider', 50)->nullable()->comment('Stripe, PayPal, Checkout.com');
            $table->string('provider_reference')->nullable();
            $table->json('provider_data')->nullable()->comment('Additional payment provider data');
            $table->datetime('issued_at');
            $table->datetime('paid_at')->nullable();
            $table->datetime('due_at')->nullable();
            $table->timestamps();
            
            // Indexes
            $table->index('user_id');
            $table->index('subscription_id');
            $table->index('status');
            $table->index('payment_provider');
            $table->index('provider_reference');
            $table->index('issued_at');
            $table->index('paid_at');
            $table->index(['user_id', 'status']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('invoices');
    }
};