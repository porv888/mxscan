<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class DmarcIngest extends Model
{
    protected $fillable = [
        'message_id',
        'attachment_name',
        'attachment_sha1',
        'mime',
        'stored_path',
        'size_bytes',
        'status',
        'error',
    ];
}
