<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class UserController extends Controller
{
    public function registration(Request $request)
    {
        try {

            try {
                $user_data = validator($request->all(), [
                    'name' => 'required',
                    'email' => 'sometimes|required|email',
                    'phone' => 'required',
                    'password' => 'required|min:8',
                    "remember_token" => "nullable|string",
                ])->validate();
            }
            catch (Exception $e) {
                try {
                    $user_data = validator($request->all(), [
                        'name' => 'required',
                        'email' => 'sometimes|required|email',
                        'phone' => 'required',
                        'password' => 'required|min:8',
                    ])->validate();
                }
                catch (Exception $ee) {
                    return 'Ошибка в почтовом адресе или пароле';
                }
            }

            if (!filter_var($user_data['email'], FILTER_VALIDATE_EMAIL)) {
                return response('Введите корректный email address', status: 400);
            }

            if (strlen($user_data['password']) < 8) {
                return response('Введите корректный пароль', status: 400);
            }
    
            if (is_null(DB::table('users')->where('email', '=', $user_data['email'])->first())) {
    
                $hash_password = Hash::make($user_data['password']);
    
                $activation_link = (string) Str::uuid();

    
                try {
                    $user_db = array(
                        'name' => $user_data['name'],
                        'email' => $user_data['email'],
                        'phone' => $user_data['phone'],
                        'password' => $hash_password,
                        'activation_link' => $activation_link,
                        'remember_token' => $user_data['remember_token']);
                }
                catch (Exception $e) {
                    $user_db = array(
                        'name' => $user_data['name'],
                        'email' => $user_data['email'],
                        'phone' => $user_data['phone'],
                        'password' => $hash_password,
                        'activation_link' => $activation_link);
                }
    
    
                if (DB::table('users')->insert($user_db)) {

                    $user = DB::table('users')->where('email', '=', $user_data['email'])->first();

                    $tokens = JWTTools::get_token($user);

                    if (!is_null(JWTTools::save_token($user->id, $tokens['refresh']))) {
                        return response()->json(array('access' => $tokens['access']), status: 200)
                        ->withCookie(cookie('refresh', $tokens['refresh'], 43200, httpOnly: true));
                    }                    
                }

                return response('ERROR!');
    
                // to do отправка сообщения по почте со специальной активационной ссылкой
                // то есть нужно передать микросервису по работе с почтой email пользователя и activation_link в сообщении
    
            }
    
            return response('Пользователь с таким почтовым адресом уже существует', status:400);

        } catch (Exception $e) {
            echo $e;
        }
    }

    public function login(Request $request)
    {
        try {
            $user_data = validator($request->all(), [
                'email' => 'sometimes|required|email',
                'password' => 'required|min:8',
            ])->validate();

            $user = DB::table('users')->where('email', '=', $user_data['email'])->first();

            if (!is_null($user)) {     

                if (Hash::check($user_data['password'], $user->password)) {
                    $tokens = JWTTools::get_token($user);

                    if (!is_null(JWTTools::save_token($user->id, $tokens['refresh']))) {

                        return response()
                        ->json(array('access' => $tokens['access'], 'message' => 'Пользователь успешно вошел в аккаунт!'))
                        ->withCookie(cookie('refresh', $tokens['refresh'], 43200, httpOnly: true));

                    } 
                }
                
                return response('Неверный пароль', status: 400);
                
            }

            return response('Такого пользователя не существует', status: 400);
            
        } catch (Exception $e) {
            echo $e;
        }
    }

    public function logout(Request $request)
    {
        try {

            $refresh = $request->cookie('refresh');

            if (!is_null($refresh)) {

                DB::table('token')->where('refresh', '=', $refresh)->delete();

                return response('Пользователь успешно покинул нас')->withoutCookie(cookie: Cookie('refresh'));
            }

            return response('Пользователь не вошел в аккаунт');

        } catch (Exception $e) {
            echo $e;
        }
    }

    public function activate($activation_link)
    {
        try {
            $user = DB::table('users')->where('activation_link', '=', $activation_link)->first();

            if (is_null($user)) {
                throw new Exception('User not found');
            }
            DB::table('users')->where('activation_link', '=', $activation_link)->update(['email_verified_at' => date('d-m-y h:i:s')]);

            return view('email_activated');
            
            
        } catch (Exception $e) {
            echo $e;
        }
    }

    public function refresh(Request $request)
    {
        try {

            $refresh = $request->cookie('refresh');

            if (is_null($refresh)) {
                return response('Пользователь не авторизован', status: 401);
            }

            if (JWTTools::is_jwt_valid($refresh, env('JWT_REFRESH_SECRET'))) {

                $token = DB::table('token')->where('refresh', '=', $refresh)->first('user_id');

                if (!is_null($token)) {

                    $user = DB::table('users')->where('id', '=', $token->user_id)->first();

                    $tokens = JWTTools::get_token($user);   
    
                    if (!is_null(JWTTools::save_token($token->user_id, $tokens['refresh']))) {
    
                        return response()->json(array('access' => $tokens['access']), status: 200)
                        ->withCookie(cookie('refresh', $tokens['refresh'], 43200, httpOnly: true));
    
                    } 
    
                    return response('Непредвиденная ошибка', status: 500);
                }
            }

            return redirect('login');

        } catch (Exception $e) {
            echo $e;
        }   
    }

    public function get_users()
    {
        try {
            $users = User::all();

            return $users;

        } catch (Exception $e) {
            echo $e;
        }
    }
}


function base64url_encode($str) {
    return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
}

class JWTTools {

    public static function save_token($user_id, $refreshToken) {

        if (!DB::table('token')->where('user_id', '=', $user_id)->get(['refresh'])->toArray() == []) {
            DB::table('token')->where('user_id', '=', $user_id)->update(['refresh' => $refreshToken]);
            return response('Токен обновлен!');
        }

        $token_db = array(
            'user_id' => $user_id,
            'refresh' => $refreshToken,
        );

        if (DB::table('token')->insert($token_db)) {
            return response('Токен сохранен!');
        }

        return null;
    }

    public static function get_token($payload) { 

        $access_payload = array(
            'user_id' => $payload->id,            
            'email' => $payload->email,            
            'exp' => (time() + 10), // 15 * 60
        );

        $refresh_payload = array(
            'user_id' => $payload->id,            
            'email' => $payload->email,            
            'exp' => (time() + 60), // 30 * 24 * 60 * 60
        );

        $jwt_access = JWTTools::generate_jwt(payload: json_encode($access_payload), secret: env("JWT_ACCESS_SECRET"));
        $jwt_refresh = JWTTools::generate_jwt(payload: json_encode($refresh_payload), secret: env("JWT_REFRESH_SECRET"));

        return [
            'access' => $jwt_access,
            'refresh' => $jwt_refresh,
        ];


    }

    private static function generate_jwt($headers = '{ "alg": "HS256", "typ": "JWT" }', string $payload, $secret = 'secret') {
        $headers_encoded = base64url_encode(json_encode($headers));
        
        $payload_encoded = base64url_encode(json_encode($payload));
        
        $signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
        $signature_encoded = base64url_encode($signature);
        
        $jwt = "$headers_encoded.$payload_encoded.$signature_encoded";
        
        return $jwt;
    }
    
    public static function is_jwt_valid($jwt, $secret = 'secret') {

        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        // получение времени жизни, jwt должен обязательно содержать поле exp
        $expiration = json_decode(json_decode($payload))->exp;

        // проверка, жив ли токен?
        $is_token_expired = ($expiration - time()) < 0;
    
        // создается подпись на основе header, payload, signature, используя секретную подпись
        $base64_url_header = base64url_encode($header);
        $base64_url_payload = base64url_encode($payload);
        $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
        $base64_url_signature = base64url_encode($signature);
    
        // проверка подписи
        $is_signature_valid = ($base64_url_signature === $signature_provided);
        
        if ($is_token_expired || !$is_signature_valid) {
            return FALSE;
        } else {
            return TRUE;
        }
    }
}
