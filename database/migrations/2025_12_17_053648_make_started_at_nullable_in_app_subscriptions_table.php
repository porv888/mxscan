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
            $table->datetime('started_at')->nullable()->change();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('app_subscriptions', function (Blueprint $table) {
            $table->datetime('started_at')->nullable(false)->change();
        });
    }
};
