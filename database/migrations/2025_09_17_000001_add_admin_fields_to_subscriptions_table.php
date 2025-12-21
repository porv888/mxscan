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
        Schema::table('subscriptions', function (Blueprint $table) {
            $table->datetime('renews_at')->nullable()->after('expires_at');
            $table->text('notes')->nullable()->after('usage_reset_at');
            
            // Update status enum to include additional statuses
            $table->dropColumn('status');
        });
        
        Schema::table('subscriptions', function (Blueprint $table) {
            $table->enum('status', ['active', 'trial', 'trialing', 'canceled', 'expired', 'past_due'])->default('trialing')->after('plan_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('subscriptions', function (Blueprint $table) {
            $table->dropColumn(['renews_at', 'notes']);
            $table->dropColumn('status');
        });
        
        Schema::table('subscriptions', function (Blueprint $table) {
            $table->enum('status', ['active', 'trial', 'canceled', 'expired'])->default('trial')->after('plan_id');
        });
    }
};
