<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            return;
        }

        $table = Schema::getConnection()->getTablePrefix() . 'incidents';

        DB::statement("ALTER TABLE `{$table}` MODIFY COLUMN `type` ENUM(
            'dmarc_fail',
            'spf_fail',
            'dkim_fail',
            'blacklist_listed',
            'high_tti',
            'record_missing',
            'rbl_listed',
            'expiry',
            'bimi_change'
        ) NOT NULL");
    }

    public function down(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            return;
        }

        $table = Schema::getConnection()->getTablePrefix() . 'incidents';

        DB::statement("ALTER TABLE `{$table}` MODIFY COLUMN `type` ENUM(
            'dmarc_fail',
            'spf_fail',
            'dkim_fail',
            'blacklist_listed',
            'high_tti',
            'record_missing',
            'rbl_listed',
            'expiry'
        ) NOT NULL");
    }
};
