<?php

namespace App\Http\Controllers;

use App\Models\Token;
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
                return 'Введите корректный email address';
            }

            if (strlen($user_data['password']) < 8) {
                return view('short_password');
            }
    
            if (DB::table('users')
            ->where('email', '=', $user_data['email'])->get(['email'])->toArray() == []) {
    
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

                    $user = DB::table('users')->where('email', '=', $user_data['email'])->get()->toArray();

                    $tokens = JWTTools::get_token($user);

                    if (!is_null(JWTTools::save_token($user[0]->id, $tokens['refresh']))) {
                        return response('Пользователь успешно зарегистрирован!', status: 200)->withCookie(cookie('refresh', $tokens['refresh'], 43200, httpOnly: true));
                    }                    
                }

                return response('ERROR!');
    
                // to do отправка сообщения по почте со специальной активационной ссылкой
    
            }
    
            return response('Пользователь с таким почтовым адресом уже существует', status:400);

        } catch (Exception $e) {
            echo $e;
        }
    }

    public function login()
    {
        try {
            

            return response('Пользователь успешно зарегистрирован!', status: 200)->withCookie(cookie('refresh', $tokens['refresh'], 43200, httpOnly: true));
        } catch (Exception $e) {
            echo $e;
        }
    }

    public function logout()
    {
        try {

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

    public function refresh()
    {
        try {

        } catch (Exception $e) {
            echo $e;
        }   
    }

    public function get_users()
    {
        try {
            $users = User::all('name', 'email');

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
            'user_id' => $payload[0]->id,            
            'email' => $payload[0]->email,            
            'exp' => (time() + 15 * 60),
        );

        $refresh_payload = array(
            'user_id' => $payload[0]->id,            
            'email' => $payload[0]->email,            
            'exp' => (time() + 30 * 24 * 60 * 60),
        );

        // 'exp' => (time() + 60)

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
    
    function is_jwt_valid($jwt, $secret = 'secret') {
        // split the jwt
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];
    
        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
        $expiration = json_decode($payload)->exp;
        $is_token_expired = ($expiration - time()) < 0;
    
        // build a signature based on the header and payload using the secret
        $base64_url_header = base64url_encode($header);
        $base64_url_payload = base64url_encode($payload);
        $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
        $base64_url_signature = base64url_encode($signature);
    
        // verify it matches the signature provided in the jwt
        $is_signature_valid = ($base64_url_signature === $signature_provided);
        
        if ($is_token_expired || !$is_signature_valid) {
            return FALSE;
        } else {
            return TRUE;
        }
    }
}
