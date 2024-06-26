<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use App\Models\User;

class AuthController extends Controller
{
    // Register
    public function register(Request $request) {

        return $user = User::create([
            'username'      => $request->input('formData.username'),
            'password'      => $request->input('formData.password'),
            'role'          => 3
        ]);
    }

    // Login
    public function login(Request $request)
    {
        if(!Auth::attempt($request->only('username', 'password'))) {
            return response()->json([
                'message' => 'Invalid username or password'
            ], 404);
        }

        $user = Auth::user();

        $token = $user->createToken('token')->plainTextToken;

        $cookie = cookie('jwt', $token, 60 * 24); // 1 day

        return response()->json([
            'message'   => 'Logged In',
            'user'      => $user
        ], 200)->withCookie($cookie);
    }

    // Check existing username
    public function checkUsername(Request $request) {
        $user = User::where("username", $request->query('username'))->first();

        if($user) {
            return response()->json([
                'exist'     => true
            ]);
        }

        return response()->json([
            'exist'     => false
        ]);
    }

    public function user()
    {
        return Auth::user();
    }

    public function logout()
    {
        $cookie = Cookie::forget('jwt');

        return response()->json([
            'message' => 'Logged out'
        ])->withCookie($cookie);
    }
}
