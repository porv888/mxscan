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
        Schema::table('users', function (Blueprint $table) {
            // Update role enum to include superadmin
            $table->dropColumn('role');
            $table->dropColumn('active');
        });
        
        Schema::table('users', function (Blueprint $table) {
            $table->enum('role', ['user', 'admin', 'superadmin'])->default('user')->after('email');
            $table->enum('status', ['active', 'suspended'])->default('active')->after('role');
            
            // Add indexes
            $table->index('role');
            $table->index('status');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropIndex(['role']);
            $table->dropIndex(['status']);
            $table->dropColumn(['role', 'status']);
        });
        
        Schema::table('users', function (Blueprint $table) {
            $table->enum('role', ['user', 'admin'])->default('user')->after('email');
            $table->boolean('active')->default(true)->after('role');
            
            $table->index('role');
            $table->index('active');
        });
    }
};