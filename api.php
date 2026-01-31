<?php
// api.php - Unified API Endpoint
// --- 1. SETUP AND CONFIGURATION ---

// Set the content type for all responses to JSON.
header('Content-Type: application/json');

// Include the database configuration. This provides the $mysqli object.
// Using require_once ensures it's only included once, even if called multiple times.
require_once 'db_config.php';


// --- 2. DATABASE INITIALIZATION ---

// This SQL block defines the structure of our database.
// Using "CREATE TABLE IF NOT EXISTS" is a safe way to ensure the tables
// are ready without causing errors on subsequent runs.
$createTablesSql = "
CREATE TABLE IF NOT EXISTS accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    sort_order INT DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(255) PRIMARY KEY,
    connection_status VARCHAR(50) NOT NULL DEFAULT 'allowed', -- 'allowed' or 'denied'
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
    server_id INT AUTO_INCREMENT PRIMARY KEY,
    local_id BIGINT, -- The original ID from the app's local database
    account_id INT NOT NULL,
    user_id INT NOT NULL,
    amount INT NOT NULL,
    timestamp DATETIME NOT NULL,
    device_id VARCHAR(255),
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);";

// We use multi_query to execute all table creation statements at once.
if (!$mysqli->multi_query($createTablesSql)) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to initialize database tables: ' . $mysqli->error]);
    exit();
}
// Clear the results from the multi_query before proceeding.
while ($mysqli->next_result()) {
    if ($result = $mysqli->store_result()) {
        $result->free();
    }
}


// --- 3. ROUTING ---

// Determine the requested action from the URL (e.g., api.php?action=ping).
$action = $_GET['action'] ?? '';


// --- 4. ACTION HANDLERS ---

switch ($action) {

    case 'ping':
        $deviceId = $_GET['deviceId'] ?? null;
        if (!$deviceId) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'deviceId is required.']);
            break;
        }

        // Check if device exists
        $stmt = $mysqli->prepare("SELECT connection_status FROM devices WHERE device_id = ?");
        $stmt->bind_param("s", $deviceId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            // Device exists, update last_seen and get its status
            $updateStmt = $mysqli->prepare("UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE device_id = ?");
            $updateStmt->bind_param("s", $deviceId);
            $updateStmt->execute();
            $connectionStatus = $result->fetch_assoc()['connection_status'];
        } else {
            // New device, register it
            $insertStmt = $mysqli->prepare("INSERT INTO devices (device_id) VALUES (?)");
            $insertStmt->bind_param("s", $deviceId);
            $insertStmt->execute();
            $connectionStatus = 'allowed'; // Default for new devices
        }

        // Return the JSON structure the app expects (PingStatusResponse)
        echo json_encode([
            'status' => 'success',
            'connectionStatus' => $connectionStatus
        ]);
        break;

    case 'login':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['status' => 'error', 'message' => 'POST request required.']);
            break;
        }

        $input = json_decode(file_get_contents('php://input'), true);
        $username = $input['username'] ?? null;
        $passwordHash = $input['passwordHash'] ?? null;

        if (!$username || !$passwordHash) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Username and passwordHash are required.']);
            break;
        }

        $stmt = $mysqli->prepare("SELECT id, password_hash FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            // Compare the app-provided hash with the one in the database
            if ($passwordHash === $user['password_hash']) {
                // Success! Return the user's ID
                echo json_encode(['status' => 'success', 'userId' => (int)$user['id']]);
            } else {
                // Wrong password
                echo json_encode(['status' => 'error', 'message' => 'Invalid username or password.']);
            }
        } else {
            // User not found
            echo json_encode(['status' => 'error', 'message' => 'Invalid username or password.']);
        }
        $stmt->close();
        break;

    case 'sync_payments':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['status' => 'error', 'message' => 'POST request required.']);
            break;
        }

        $payments = json_decode(file_get_contents('php://input'), true);
        $sync_results = [];

        $stmt = $mysqli->prepare("INSERT INTO payments (local_id, account_id, user_id, amount, timestamp, device_id) VALUES (?, ?, ?, ?, ?, ?)");

        foreach ($payments as $p) {
            $datetime = date("Y-m-d H:i:s", $p['timestamp'] / 1000);
            $stmt->bind_param("iiiiss", $p['id'], $p['accountId'], $p['userId'], $p['amount'], $datetime, $p['deviceId']);
            if ($stmt->execute()) {
                // Return the mapping of the app's local ID to the new server ID
                $sync_results[] = ['localId' => (int)$p['id'], 'serverId' => (int)$mysqli->insert_id];
            }
        }
        $stmt->close();
        echo json_encode($sync_results);
        break;

    case 'get_accounts':
        $result = $mysqli->query("SELECT id, name, is_active AS active, sort_order AS sortOrder FROM accounts WHERE is_active = TRUE ORDER BY sort_order;");
        $accounts = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $row['id'] = (int)$row['id'];
                $row['active'] = (bool)$row['active'];
                $row['sortOrder'] = (int)$row['sortOrder'];
                $accounts[] = $row;
            }
        }
        echo json_encode($accounts);
        break;

    case 'get_users':
        $result = $mysqli->query("SELECT id, username AS name FROM users;");
        $users = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $row['id'] = (int)$row['id'];
                $users[] = $row;
            }
        }
        echo json_encode($users);
        break;

    default:
        // Handle unknown or missing actions
        http_response_code(400);
        echo json_encode(['error' => "Unknown or missing action parameter. Available actions: 'ping', 'login', 'sync_payments', 'get_accounts', 'get_users'."]);
        break;
}

// --- 5. CLEANUP ---
$mysqli->close();
?>
