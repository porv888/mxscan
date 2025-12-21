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
        Schema::create('settings', function (Blueprint $table) {
            $table->id();
            $table->string('key_name', 100)->unique();
            $table->text('value')->nullable();
            $table->string('type', 20)->default('string')->comment('string, integer, boolean, json');
            $table->text('description')->nullable();
            $table->boolean('is_public')->default(false)->comment('Can be accessed by non-admin users');
            $table->timestamps();
            
            // Indexes
            $table->index('key_name');
            $table->index('type');
            $table->index('is_public');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('settings');
    }
};