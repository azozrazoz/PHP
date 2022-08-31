<?php

namespace App\Http\Middleware;

use App\Http\Controllers\JWTTools;
use App\Http\Controllers\UserController;
use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

class UserMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $authorizationHeader = $request->header('Authorization');   

            if (!$authorizationHeader) {
                throw new Exception('Пользователь не аутетифицирован');
            }

            $access_token = explode(' ', $authorizationHeader)[1];

            if (!$access_token) {
                throw new Exception('Пользователь не аутетифицирован');
            }

            if (!JWTTools::is_jwt_valid($access_token, env('JWT_ACCESS_SECRET'))) {
                echo 'токен умер';
                return Redirect::to('api/refresh');
            }

            return $next($request);
            
        } catch (Exception $e) {
            return response($e->getMessage(), status: 401);
        }
        
        return $next($request);
    }
}
