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
            $table->string('stripe_id')->nullable()->unique()->after('plan_id');
            $table->string('stripe_status')->nullable()->after('stripe_id');
            $table->string('stripe_price')->nullable()->after('stripe_status');
            $table->integer('quantity')->nullable()->after('stripe_price');
            $table->timestamp('trial_ends_at')->nullable()->after('quantity');
            $table->timestamp('ends_at')->nullable()->after('trial_ends_at');
            $table->string('type')->nullable()->after('ends_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('app_subscriptions', function (Blueprint $table) {
            $table->dropColumn([
                'stripe_id',
                'stripe_status', 
                'stripe_price',
                'quantity',
                'trial_ends_at',
                'ends_at',
                'type'
            ]);
        });
    }
};
