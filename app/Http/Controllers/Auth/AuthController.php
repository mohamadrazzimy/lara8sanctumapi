<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request)
    {

        $validatedData = $request->validate([
            "name" => "required|string|max:255",
            "email" => "required|string|email|max:255|unique:users",
            "password" => "required|string|min:8",
        ]);

        $user = User::create([
            "name" => $validatedData["name"],
            "email" => $validatedData["email"],
            "password" => Hash::make($validatedData["password"]),
        ]);

        $token = $user->createToken("auth_token")->plainTextToken;

        return response()->json([
            "access_token" => $token,
            "token_type" => "Bearer",
        ]);
    }

protected function failedValidation(\Illuminate\Contracts\Validation\Validator $validator)
{
    $response = new Response(['error' => $validator->errors()->first()], 422);
    throw new ValidationException($validator, $response);
}

    public function login(Request $request)
    {
        if (!Auth::attempt($request->only("email", "password"))) {
            return response()->json(
                [
                    "message" => "Invalid login details",
                ],
                401
            );
        }

        $user = User::where("email", $request["email"])->firstOrFail();

        $token = $user->createToken("auth_token")->plainTextToken;

        return response()->json([
            "access_token" => $token,
            "token_type" => "Bearer",
        ]);
    }

    public function me(Request $request)
    {
        return $request->user();
    }
}