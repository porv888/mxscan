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
        Schema::table('delivery_checks', function (Blueprint $table) {
            $table->json('auth_meta')->nullable()->after('raw_headers');
            $table->text('ar_raw')->nullable()->after('auth_meta');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('delivery_checks', function (Blueprint $table) {
            $table->dropColumn(['auth_meta', 'ar_raw']);
        });
    }
};
