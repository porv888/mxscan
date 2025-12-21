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
            // Add unique index on (delivery_monitor_id, message_id) to prevent duplicates
            $table->unique(['delivery_monitor_id', 'message_id'], 'delivery_checks_monitor_message_unique');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('delivery_checks', function (Blueprint $table) {
            //
        });
    }
};
