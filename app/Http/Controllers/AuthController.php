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
            'username'      => $request->input('username'),
            'password'      => $request->input('password'),
            'role'          => 3
        ]);
    }

    // Login
    public function login(Request $request)
    {
        if(!Auth::attempt($request->only('username', 'password'))) {
            return response()->json([
                'message' => 'Invalid credentials'
            ], 401);
        }

        $user = Auth::user();

        $token = $user->createToken('token')->plainTextToken;

        $cookie = cookie('jwt', $token, 60 * 24); // 1 day
        $userRole = cookie('userRole', $user->role, 60 * 24); // 1 day

        return response()->json([
            'message' => 'Logged In'
        ], 200)->withCookie($cookie)->withCookie($userRole);
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
        $userRole = Cookie::forget('userRole');

        return response()->json([
            'message' => 'Logged out'
        ])->withCookie($cookie)->withCookie($userRole);
    }
}
