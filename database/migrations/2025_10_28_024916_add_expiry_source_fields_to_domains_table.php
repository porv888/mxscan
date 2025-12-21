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
            $table->string('domain_expiry_source')->nullable()->after('domain_expires_at');
            $table->timestamp('domain_expiry_detected_at')->nullable()->after('domain_expiry_source');
            $table->string('ssl_expiry_source')->nullable()->after('ssl_expires_at');
            $table->timestamp('ssl_expiry_detected_at')->nullable()->after('ssl_expiry_source');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('domains', function (Blueprint $table) {
            $table->dropColumn([
                'domain_expiry_source',
                'domain_expiry_detected_at',
                'ssl_expiry_source',
                'ssl_expiry_detected_at',
            ]);
        });
    }
};
