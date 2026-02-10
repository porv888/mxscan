<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('notification_prefs', function (Blueprint $table) {
            $table->boolean('webhook_enabled')->default(false)->after('slack_webhook');
            $table->string('webhook_url', 500)->nullable()->after('webhook_enabled');
            $table->string('webhook_secret', 100)->nullable()->after('webhook_url');
        });
    }

    public function down(): void
    {
        Schema::table('notification_prefs', function (Blueprint $table) {
            $table->dropColumn(['webhook_enabled', 'webhook_url', 'webhook_secret']);
        });
    }
};
