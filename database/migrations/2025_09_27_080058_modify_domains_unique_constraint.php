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
        Schema::table('domains', function (Blueprint $table) {
            // Drop the existing unique constraint on domain
            $table->dropUnique(['domain']);
            
            // Add a composite unique constraint on user_id + domain
            $table->unique(['user_id', 'domain'], 'domains_user_domain_unique');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('domains', function (Blueprint $table) {
            // Drop the composite unique constraint
            $table->dropUnique('domains_user_domain_unique');
            
            // Restore the original unique constraint on domain
            $table->unique('domain');
        });
    }
};
