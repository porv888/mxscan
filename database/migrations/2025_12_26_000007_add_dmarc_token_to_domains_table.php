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
            // Unique token for DMARC RUA address: dmarc+<token>@mxscan.me
            $table->string('dmarc_token', 32)->nullable()->unique()->after('status');
            
            // Track when DMARC reports were last received
            $table->timestamp('dmarc_last_report_at')->nullable()->after('dmarc_token');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('domains', function (Blueprint $table) {
            $table->dropColumn(['dmarc_token', 'dmarc_last_report_at']);
        });
    }
};
