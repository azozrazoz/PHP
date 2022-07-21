<?php

use App\Http\Controllers\FirstController;
use App\Http\Controllers\SecondController;
use App\Http\Controllers\UserInfoController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::get('lesson/3', [FirstController::class, 'lesson']);
Route::get('calculator', [SecondController::class, 'calc']);

// User
Route::get('user/create', [FirstController::class, 'create']);
Route::get('users', [FirstController::class, 'list']);
Route::get('user/{id}', [FirstController::class, 'item']);
Route::post('user/{id}', [FirstController::class, 'item']);
Route::put('user/{id}', [FirstController::class, 'item']);
Route::delete('user/{id}', [FirstController::class, 'item']);

// UserInfo
Route::get('usersInfo/read', [UserInfoController::class, 'read']);
Route::get('usersInfo/create', [UserInfoController::class, 'create']);
Route::get('usersInfo/update/{id}', [UserInfoController::class, 'update']);
Route::get('usersInfo/delete/{id}', [UserInfoController::class, 'delete']);

