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
        Schema::create('monitor_folder_positions', function (Blueprint $table) {
            $table->id();
            $table->string('folder_name')->unique();
            $table->unsignedBigInteger('last_uid')->default(0);
            $table->timestamps();
            
            $table->index('folder_name');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('monitor_folder_positions');
    }
};
