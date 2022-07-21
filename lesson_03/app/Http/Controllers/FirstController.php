<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use App\Models\UserInfo;

class FirstController extends Controller
{
    public function create(Request $request) {
        $new_user = new User();
        $new_user->name = $request->name;
        $new_user->email = $request->email;
        $new_user->password = $request->password;
        $new_user->save();
    }

    public function list() {
        $user = User::get();

        return $user;
    }

    public function item($id) {
        $user = User::where('id', $id)->with('userInfo')->first();

        return $user;
    }

    public function lesson(Request $request)
    {
        // dump($request->name);
        // return "Hello browser";

        // $user = User::where('id', 1)->first();
        

        // $user_with_info = User::with('userInfo')->get();

    }
}