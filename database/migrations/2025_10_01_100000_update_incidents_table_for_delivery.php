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
        Schema::table('incidents', function (Blueprint $table) {
            // Add delivery_check_id for linking to delivery checks
            $table->foreignId('delivery_check_id')->nullable()->after('domain_id')->constrained()->cascadeOnDelete();
            
            // Update kind to use enum with delivery-specific types
            $table->dropColumn('kind');
        });
        
        Schema::table('incidents', function (Blueprint $table) {
            $table->enum('type', [
                'dmarc_fail', 
                'spf_fail', 
                'dkim_fail', 
                'blacklist_listed', 
                'high_tti',
                'record_missing',
                'rbl_listed',
                'expiry'
            ])->after('delivery_check_id');
            
            // Update severity enum to match spec (warning|incident instead of info|warning|critical)
            $table->dropColumn('severity');
        });
        
        Schema::table('incidents', function (Blueprint $table) {
            $table->enum('severity', ['warning', 'incident'])->default('warning')->after('type');
            
            // Add occurred_at timestamp
            $table->timestamp('occurred_at')->nullable()->after('severity');
            
            // Rename context to meta
            $table->renameColumn('context', 'meta');
            
            // Add new indexes
            $table->index(['domain_id', 'occurred_at']);
            $table->index(['type', 'occurred_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('incidents', function (Blueprint $table) {
            $table->dropForeign(['delivery_check_id']);
            $table->dropColumn(['delivery_check_id', 'occurred_at']);
            $table->dropIndex(['domain_id', 'occurred_at']);
            $table->dropIndex(['type', 'occurred_at']);
            $table->renameColumn('meta', 'context');
        });
    }
};
