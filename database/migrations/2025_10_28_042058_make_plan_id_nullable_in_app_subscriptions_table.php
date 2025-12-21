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
        Schema::table('app_subscriptions', function (Blueprint $table) {
            // Make plan_id nullable to allow Cashier to create subscriptions
            // The webhook handler will backfill the plan_id based on the Stripe price
            $table->unsignedBigInteger('plan_id')->nullable()->change();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('app_subscriptions', function (Blueprint $table) {
            // Revert plan_id to NOT NULL
            $table->unsignedBigInteger('plan_id')->nullable(false)->change();
        });
    }
};
