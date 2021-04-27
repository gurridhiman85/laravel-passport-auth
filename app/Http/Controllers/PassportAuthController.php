<?php

namespace App\Http\Controllers;

use App\Models\Invitation;
use Carbon\Carbon;
use Illuminate\Http\Request;
use App\Models\User;
use Crypt;
use phpseclib3\Crypt\Hash;

class PassportAuthController extends Controller
{
    /**
     * Registration
     */
    public function register_old(Request $request)
    {
        $this->validate($request, [
            'name' => 'required|min:4',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $token = $user->createToken('LaravelAuthApp')->accessToken;

        return response()->json(['token' => $token], 200);
    }

    /**
     * Registration
     */
    public function sendInvitation(Request $request)
    {
        $this->validate($request, [
            'email' => 'required|email|unique:users,email',
        ]);

        if(auth()->user()->user_role == 'admin'){
            Invitation::create([
                'email' => $request->email,
                'is_registered' => 0,
                'link' => Crypt::encrypt($request->email),
            ]);

            return response()->json(['message' => 'Invitation sent successfully'], 200);
        }else{
            return response()->json(['message' => 'you don\'t have access'], 404);
        }

    }

    /**
     * Registration
     */
    public function register($enc_email,Request $request)
    {
        $email = Crypt::decrypt($enc_email);
        //dd($email);
        $this->validate($request, [
            //'name' => 'required|min:4',
            //'email' => 'required|email',
            'password' => 'required|min:8',
        ]);

        $invite = Invitation::where('email',$email)->where('is_registered',0)->first();
        if(!$invite){
            return response()->json(['message' => 'User doesn\'t found'], 404);
        }

        $user = User::create([
            //'name' => $request->name,
            'email' => $email,
            'user_role' => 'user',
            'password' => bcrypt($request->password),
            'email_verification_code' => rand(0,1000000)
        ]);

        $invite->delete();
        //$token = $user->createToken('LaravelAuthApp')->accessToken;

        return response()->json(['message' => 'Please check the registered email for otp verification'], 200);
    }

    public function emailVerify($enc_email,Request $request){
        $email = Crypt::decrypt($enc_email);

        $this->validate($request, [
            'email_otp_code' => 'required|min:6|max:6',
        ]);
        $user = User::where('email',$email)->first();
        if(!$user){
            return response()->json(['message' => 'User doesn\'t found'], 404);
        }

        $user->email_verified_at = Carbon::now();
        $user->save();
        return response()->json(['message' => 'User registered and verified successfully'], 200);
    }

    /**
     * Login
     */
    public function login(Request $request)
    {
        $data = [
            'email' => $request->email,
            'password' => $request->password
        ];

        if (auth()->attempt($data)) {
            if(is_null(auth()->user()->email_verified_at)){
                return response()->json(['message' => 'you don\'t have access'], 404);
            }
            $token = auth()->user()->createToken('LaravelAuthApp')->accessToken;
            return response()->json(['token' => $token], 200);
        } else {
            return response()->json(['error' => 'Unauthorised'], 401);
        }
    }

    public function logout (Request $request) {
        $token = $request->user()->token();
        $token->revoke();
        $response = ['message' => 'You have been successfully logged out!'];
        return response($response, 200);
    }

    public function profile(Request $request){
        $this->validate($request, [
            'name' => 'required|min:4',
            'avatar' => 'image|mimes:jpg,png,jpeg,gif,svg|max:2048|dimensions:min_width=256,min_height=256,max_width=256,max_height=256',
        ]);

        $user = User::find(auth()->user()->id);

        if(!$request->hasFile('avatar')) {
            return response()->json(['upload_file_not_found'], 400);
        }
        $file = $request->file('avatar');
        if(!$file->isValid()) {
            return response()->json(['invalid_file_upload'], 400);
        }

        if($request->hasfile('avatar')) {
            $file = $request->file('avatar');
            $avatar = $file->getClientOriginalName();
            $file->move(public_path() . '/uploads/', $avatar);
            $user->avatar = '/uploads/'.$avatar;
        }
        $user->name = $request->name;
        $user->save();
        return response()->json(['message' => 'Profile updated successfully'], 200);
    }
}
