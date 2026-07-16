<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('domains', function (Blueprint $table) {
            $table->string('dns_provider', 40)->nullable()->after('provider_guess');
            $table->timestamp('dns_provider_confirmed_at')->nullable()->after('dns_provider');
        });
    }

    public function down(): void
    {
        Schema::table('domains', function (Blueprint $table) {
            $table->dropColumn(['dns_provider', 'dns_provider_confirmed_at']);
        });
    }
};
