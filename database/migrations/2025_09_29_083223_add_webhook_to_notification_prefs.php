<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('notification_prefs')) {
            return;
        }

        Schema::table('notification_prefs', function (Blueprint $table) {
            if (! Schema::hasColumn('notification_prefs', 'webhook_enabled')) {
                $table->boolean('webhook_enabled')->default(false)->after('slack_webhook');
            }
            if (! Schema::hasColumn('notification_prefs', 'webhook_url')) {
                $table->string('webhook_url', 500)->nullable()->after('webhook_enabled');
            }
            if (! Schema::hasColumn('notification_prefs', 'webhook_secret')) {
                $table->string('webhook_secret', 100)->nullable()->after('webhook_url');
            }
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('notification_prefs')) {
            return;
        }

        Schema::table('notification_prefs', function (Blueprint $table) {
            $cols = [];
            foreach (['webhook_enabled', 'webhook_url', 'webhook_secret'] as $col) {
                if (Schema::hasColumn('notification_prefs', $col)) {
                    $cols[] = $col;
                }
            }
            if ($cols !== []) {
                $table->dropColumn($cols);
            }
        });
    }
};
