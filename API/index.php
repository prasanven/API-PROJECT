<?php
// index.php

header("Content-Type: application/json");
header("Access-Control-Allow-Methods: POST, GET");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

$requestMethod = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? null;

$dataFile = 'data.json';

if (!file_exists($dataFile)) {
    file_put_contents($dataFile, json_encode([]));
}

function readData($file) {
    return json_decode(file_get_contents($file), true);
}

function writeData($file, $data) {
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

// Handle API Actions
switch ($action) {
    case 'register':
        if ($requestMethod === 'POST') {
            registerUser($dataFile);
        } else {
            respond(['error' => 'Invalid request method.'], 405);
        }
        break;
    case 'login':
        if ($requestMethod === 'POST') {
            loginUser($dataFile);
        } else {
            respond(['error' => 'Invalid request method.'], 405);
        }
        break;
    case 'data':
        if ($requestMethod === 'GET') {
            fetchData($dataFile);
        } else {
            respond(['error' => 'Invalid request method.'], 405);
        }
        break;
    default:
        respond(['error' => 'Invalid action.'], 400);
        break;
}

function registerUser($file) {
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'] ?? null;
    $password = $input['password'] ?? null;

    if (!$username || !$password) {
        respond(['error' => 'Username and password are required.'], 400);
    }

    $data = readData($file);

    foreach ($data as $user) {
        if ($user['username'] === $username) {
            respond(['error' => 'User already exists.'], 409);
        }
    }

    $token = bin2hex(random_bytes(16));
    $data[] = ['username' => $username, 'password' => password_hash($password, PASSWORD_BCRYPT), 'token' => $token];
    writeData($file, $data);

    respond(['message' => 'User registered successfully.', 'token' => $token], 201);
}

function loginUser($file) {
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'] ?? null;
    $password = $input['password'] ?? null;

    if (!$username || !$password) {
        respond(['error' => 'Username and password are required.'], 400);
    }

    $data = readData($file);

    foreach ($data as $user) {
        if ($user['username'] === $username && password_verify($password, $user['password'])) {
            respond(['message' => 'Login successful.', 'token' => $user['token']]);
        }
    }

    respond(['error' => 'Invalid credentials.'], 401);
}

function fetchData($file) {
    $headers = getallheaders();
    $token = $headers['Authorization'] ?? null;

    if (!$token) {
        respond(['error' => 'Authorization token is required.'], 401);
    }

    // Remove "Bearer " prefix from token
    if (strpos($token, 'Bearer ') === 0) {
        $token = substr($token, 7); // Remove 'Bearer ' from the token
    } else {
        respond(['error' => 'Invalid token format.'], 400);
    }

    // Read the user data from the file
    $data = readData($file);

    foreach ($data as $user) {
        if ($user['token'] === $token) {
            // Return more meaningful data like AbuseIPDB style response
            $response = [
                'data' => [
                    'message' => 'Access granted',
                    'ip' => '192.168.1.1',  // For example, static IP data
                    'hostname' => 'example.com',
                    'abuse_count' => 3,  // This could be fetched from a report or abuse data
                    'last_reported' => '2024-12-15T12:34:56Z',  // Last reported time
                    'country' => 'US',
                    'isp' => 'ISP Name'
                ]
            ];
            respond($response);
        }
    }

    respond(['error' => 'Invalid token.'], 403);  // If token not found, return an error
}


function respond($response, $status = 200) {
    http_response_code($status);
    echo json_encode($response);
    exit;
}
