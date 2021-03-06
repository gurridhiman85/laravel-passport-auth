<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PassportAuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/


Route::post('register/{enc_email}', [PassportAuthController::class, 'register']);
Route::post('emailverify/{enc_email}', [PassportAuthController::class, 'emailVerify']);
//Route::post('register', [PassportAuthController::class, 'register']);
Route::post('login', [PassportAuthController::class, 'login']);
Route::post('logout', [PassportAuthController::class, 'logout']);

/*Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});*/

Route::middleware('auth:api')->group(function () {
    Route::post('sendinvitation', [PassportAuthController::class, 'sendInvitation']);
    Route::post('profile', [PassportAuthController::class, 'profile']);
});

