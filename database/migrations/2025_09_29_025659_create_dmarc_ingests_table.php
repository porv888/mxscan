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
        Schema::create('dmarc_ingests', function (Blueprint $table) {
            $table->id();
            $table->string('message_id')->nullable()->index();
            $table->string('attachment_name');
            $table->string('attachment_sha1', 40)->index();
            $table->string('mime')->nullable();
            $table->string('stored_path'); // storage relative path
            $table->unsignedInteger('size_bytes');
            $table->string('status')->default('stored'); // stored|forwarded|parsed|failed
            $table->text('error')->nullable();
            $table->timestamps();

            $table->unique(['message_id', 'attachment_sha1']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dmarc_ingests');
    }
};
