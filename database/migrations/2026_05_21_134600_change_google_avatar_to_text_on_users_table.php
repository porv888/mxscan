<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $usersTable = Schema::getConnection()->getTablePrefix() . 'users';
        DB::statement("ALTER TABLE `{$usersTable}` MODIFY google_avatar TEXT NULL");
    }

    public function down(): void
    {
        $usersTable = Schema::getConnection()->getTablePrefix() . 'users';
        DB::statement("ALTER TABLE `{$usersTable}` MODIFY google_avatar VARCHAR(255) NULL");
    }
};
