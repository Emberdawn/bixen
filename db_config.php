<?php
// --- DATABASE CONNECTION SETTINGS ---
// This file contains the connection details for your database.
// By keeping it in a separate file, you can easily manage your credentials
// without changing the main logic of your application endpoints.

// **IMPORTANT**: The hostname is almost always 'localhost' because the PHP script
// is running on the same server as the database.
define('DB_HOST', 'localhost');

// The name of your database.
define('DB_NAME', 'emberpro_bixenskasse');

// The username for your database.
define('DB_USER', 'emberpro_androidadmin');

// **VERY IMPORTANT**: Replace this placeholder with your actual database password.
define('DB_PASSWORD', 'Hemmelig1337!');


// --- DATABASE INITIALIZATION AND CONNECTION ---
// This section creates a new database connection object (using the MySQLi extension).
// It's the standard, secure way to interact with a MySQL database in PHP.
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

// Check if the connection failed. If it did, the script will stop and
// send back a JSON error message, which is helpful for debugging.
if ($mysqli->connect_error) {
    // Set the HTTP response code to 500 (Internal Server Error).
    http_response_code(500);
    // Send a JSON response explaining the error.
    header('Content-Type: application/json');
    echo json_encode(['error' => "Database connection failed: " . $mysqli->connect_error]);
    // Stop the script.
    exit();
}

// Ensure the connection uses the UTF-8 character set, which is essential
// for handling international characters correctly (like æ, ø, å).
$mysqli->set_charset("utf8mb4");

?>