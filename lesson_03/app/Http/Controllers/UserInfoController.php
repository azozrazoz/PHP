<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\UserInfo;

class UserInfoController extends Controller
{
    public function create(Request $request) {
        $userInfo = new UserInfo();
        $userInfo->full_name = $request->full_name;
        $userInfo->info = $request->info;
        $userInfo->user_id = $request->user_id;
        $userInfo->save();
    }

    public function read() {
        $userInfo = UserInfo::get();
        return $userInfo;
    }

    public function update($id, Request $request) {
        $userInfo = UserInfo::find($id);
        $userInfo->full_name = $request->full_name;
        $userInfo->info = $request->info;
        $userInfo->user_id = $request->user_id;
        $userInfo->update();
    }

    public function delete($id) {
        $userInfo = UserInfo::find($id);
        $userInfo->delete();
    }
}
