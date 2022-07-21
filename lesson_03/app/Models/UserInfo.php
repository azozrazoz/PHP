<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class UserInfo extends Model
{

    protected $table = 'user_info';
    public $timestamps = false;
    use HasFactory; 
}
