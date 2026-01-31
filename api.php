<?php
// This is a unified API endpoint that handles multiple actions.

// 1. --- SETUP AND CONFIGURATION ---
// Set the content type for all responses to JSON.
header('Content-Type: application/json');

// Include the database configuration. This provides the $mysqli object.
require_once 'db_config.php';


// 2. --- INITIALIZE DATABASE TABLES ---
// For robustness, we ensure all required tables exist on startup.
// This block will run on every request, but the "IF NOT EXISTS" clause
// means it will only create the tables on the very first run.

// ADDED: A new table to store device information.
$createTablesSql = "
CREATE TABLE IF NOT EXISTS accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS payments (
    server_id INT AUTO_INCREMENT PRIMARY KEY,
    account_id INT NOT NULL,
    user_id INT NOT NULL,
    amount INT NOT NULL,
    `timestamp` DATETIME NOT NULL,
    local_id BIGINT,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(255) PRIMARY KEY,
    connection_status VARCHAR(50) NOT NULL DEFAULT 'allowed',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS debug_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message TEXT NULL,
    method VARCHAR(10) NULL,
    action VARCHAR(100) NULL,
    content_type VARCHAR(255) NULL,
    query_params TEXT NULL,
    json_payload TEXT NULL,
    raw_body MEDIUMTEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS debug_settings (
    `key` VARCHAR(100) PRIMARY KEY,
    `value` VARCHAR(10) NOT NULL
);";

// The mysqli_multi_query function allows us to execute all CREATE TABLE statements at once.
if (!$mysqli->multi_query($createTablesSql)) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to initialize database tables: ' . $mysqli->error]);
    exit();
}
// We need to clear the results of the multi-query before proceeding.
while ($mysqli->next_result()) {
    if ($result = $mysqli->store_result()) {
        $result->free();
    }
}

$mysqli->query("INSERT IGNORE INTO debug_settings (`key`, `value`) VALUES ('enabled', '1');");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN message TEXT NULL");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN method VARCHAR(10) NULL");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN action VARCHAR(100) NULL");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN content_type VARCHAR(255) NULL");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN query_params TEXT NULL");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN json_payload TEXT NULL");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN raw_body MEDIUMTEXT NULL");
$mysqli->query("ALTER TABLE debug_logs ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");


// 3. --- ROUTING: DETERMINE THE ACTION ---
// We use a URL parameter '?action=...' to decide what to do.
$action = $_GET['action'] ?? ''; // Safely get the action, default to empty string.
$rawBody = file_get_contents('php://input');
$jsonInput = null;
if ($rawBody !== '') {
    $decoded = json_decode($rawBody, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        $jsonInput = $decoded;
    }
}

$isDebugLoggingEnabled = function ($mysqli) {
    $stmt = $mysqli->prepare("SELECT value FROM debug_settings WHERE `key` = 'enabled'");
    $stmt->execute();
    $result = $stmt->get_result();
    $value = '0';
    if ($result && $row = $result->fetch_assoc()) {
        $value = $row['value'] ?? '0';
    }
    $stmt->close();
    return $value === '1';
};

$logIncomingRequest = function ($mysqli, $action, $rawBody, $jsonInput) use ($isDebugLoggingEnabled) {
    if (!$isDebugLoggingEnabled($mysqli)) {
        return;
    }

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    $isJson = stripos($contentType, 'application/json') !== false;

    if ($method !== 'POST' && !$isJson) {
        return;
    }

    $queryParams = !empty($_GET) ? json_encode($_GET) : null;
    $jsonPayload = is_array($jsonInput) ? json_encode($jsonInput) : null;
    $rawBodyValue = $rawBody !== '' ? $rawBody : null;
    $message = sprintf('request logged: %s %s', $method, $action ?: 'unknown');

    $stmt = $mysqli->prepare(
        "INSERT INTO debug_logs (message, method, action, content_type, query_params, json_payload, raw_body) " .
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    );
    $stmt->bind_param("sssssss", $message, $method, $action, $contentType, $queryParams, $jsonPayload, $rawBodyValue);
    $stmt->execute();
    $stmt->close();
};

$logIncomingRequest($mysqli, $action, $rawBody, $jsonInput);

// 3b. --- PASSWORD HELPERS ---
$isSha256Hex = function ($value) {
    return is_string($value) && preg_match('/^[a-f0-9]{64}$/i', $value) === 1;
};

$normalizePasswordHash = function ($password) use ($isSha256Hex) {
    if ($isSha256Hex($password)) {
        return strtolower($password);
    }
    return hash('sha256', $password);
};


// 4. --- ACTION HANDLER ---
// A switch statement directs the request to the correct block of code.
switch ($action) {
    case 'ping':
        // UPDATED: This action now handles device registration and status checks.
        $deviceId = $_GET['deviceId'] ?? null;
        if (!$deviceId) {
            http_response_code(400);
            echo json_encode(['error' => 'deviceId is required for the ping action.']);
            break;
        }

        // Use a prepared statement to prevent SQL injection.
        $stmt = $mysqli->prepare("SELECT connection_status FROM devices WHERE device_id = ?");
        $stmt->bind_param("s", $deviceId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            // Device exists, fetch its status.
            $row = $result->fetch_assoc();
            $connectionStatus = $row['connection_status'];
            // Also update the 'last_seen' timestamp.
            $updateStmt = $mysqli->prepare("UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE device_id = ?");
            $updateStmt->bind_param("s", $deviceId);
            $updateStmt->execute();
            $updateStmt->close();
        } else {
            // New device, insert it with the default status 'allowed'.
            $insertStmt = $mysqli->prepare("INSERT INTO devices (device_id) VALUES (?)");
            $insertStmt->bind_param("s", $deviceId);
            $insertStmt->execute();
            $insertStmt->close();
            $connectionStatus = 'allowed'; // Default status for new devices.
        }
        $stmt->close();

        // Return the required JSON structure for the app.
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

        $input = is_array($jsonInput) ? $jsonInput : [];
        $username = $input['username'] ?? null;
        $password = $input['password'] ?? null;

        if (!$username || !$password) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Username and password are required.']);
            break;
        }

        $stmt = $mysqli->prepare("SELECT id, password_hash FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $storedHash = $user['password_hash'];
            $normalizedPassword = $normalizePasswordHash($password);
            $passwordMatches = false;

            if (preg_match('/^\$2y\$/', $storedHash) === 1) {
                $passwordMatches = password_verify($password, $storedHash)
                    || password_verify($normalizedPassword, $storedHash);
            } else {
                $passwordMatches = hash_equals($storedHash, $normalizedPassword);
            }
            if ($passwordMatches) {
                echo json_encode(['status' => 'success', 'userId' => (int)$user['id']]);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Invalid username or password.']);
            }
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Invalid username or password.']);
        }
        $stmt->close();
        break;

    case 'get_accounts':
        // Action: Fetch all active accounts. (No changes needed)
        $result = $mysqli->query("SELECT id, name, is_active FROM accounts WHERE is_active = TRUE;");
        $accounts = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $accounts[] = ['id' => (int)$row['id'], 'name' => $row['name'], 'active' => (bool)$row['is_active']];
            }
        }
        echo json_encode($accounts);
        break;

    case 'get_users':
        // Action: Fetch all users.
        $result = $mysqli->query("SELECT id, username, role FROM users;");
        $users = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $users[] = [
                    'id' => (int)$row['id'],
                    'name' => $row['username'],
                    'role' => $row['role']
                ];
            }
        }
        echo json_encode($users);
        break;

    case 'add_user':
        // Action: Create a new user.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'The add_user action requires a POST request.']);
            break;
        }

        $input = is_array($jsonInput) ? $jsonInput : [];
        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';
        $role = $input['role'] ?? 'user';

        if ($username === '' || $password === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Username and password are required.']);
            break;
        }

        if (!in_array($role, ['user', 'admin'], true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Role must be either user or admin.']);
            break;
        }

        $passwordHash = $normalizePasswordHash($password);
        $stmt = $mysqli->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $passwordHash, $role);

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'id' => (int)$mysqli->insert_id]);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to create user.']);
        }
        $stmt->close();
        break;

    case 'update_user':
        // Action: Update an existing user.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'The update_user action requires a POST request.']);
            break;
        }

        $input = is_array($jsonInput) ? $jsonInput : [];
        $userId = isset($input['id']) ? (int)$input['id'] : 0;
        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';
        $role = $input['role'] ?? 'user';

        if ($userId <= 0 || $username === '') {
            http_response_code(400);
            echo json_encode(['error' => 'User id and username are required.']);
            break;
        }

        if (!in_array($role, ['user', 'admin'], true)) {
            http_response_code(400);
            echo json_encode(['error' => 'Role must be either user or admin.']);
            break;
        }

        if ($password !== '') {
            $passwordHash = $normalizePasswordHash($password);
            $stmt = $mysqli->prepare("UPDATE users SET username = ?, role = ?, password_hash = ? WHERE id = ?");
            $stmt->bind_param("sssi", $username, $role, $passwordHash, $userId);
        } else {
            $stmt = $mysqli->prepare("UPDATE users SET username = ?, role = ? WHERE id = ?");
            $stmt->bind_param("ssi", $username, $role, $userId);
        }

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to update user.']);
        }
        $stmt->close();
        break;

    case 'get_payments':
        // NEW Action: Fetch payment entries with account and user information.
        $result = $mysqli->query(
            "SELECT payments.server_id, payments.local_id, payments.amount, payments.`timestamp`, " .
            "accounts.name AS account_name, users.username AS user_name " .
            "FROM payments " .
            "JOIN accounts ON payments.account_id = accounts.id " .
            "JOIN users ON payments.user_id = users.id " .
            "ORDER BY payments.`timestamp` DESC;"
        );
        $payments = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $payments[] = $row;
            }
        }
        echo json_encode($payments);
        break;

    case 'sync_payments':
        // Action: Receive and save payment data from the app. (No changes needed)
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'The sync_payments action requires a POST request.']);
            break;
        }
        
        $payments_from_app = is_array($jsonInput) ? $jsonInput : [];
        $sync_results = [];

        $stmt = $mysqli->prepare("INSERT INTO payments (local_id, account_id, user_id, amount, `timestamp`) VALUES (?, ?, ?, ?, ?)");
        
        if ($payments_from_app && $stmt) {
            foreach ($payments_from_app as $payment) {
                $datetime = date("Y-m-d H:i:s", $payment['timestamp'] / 1000);
                $stmt->bind_param("iiiis", $payment['id'], $payment['accountId'], $payment['userId'], $payment['amount'], $datetime);
                if ($stmt->execute()) {
                    $sync_results[] = ['localId' => (int)$payment['id'], 'serverId' => (int)$mysqli->insert_id];
                }
            }
            $stmt->close();
        }
        echo json_encode($sync_results);
        break;

    // --- NEW ACTIONS FOR DEVICE MANAGEMENT ---

    case 'get_devices':
        // NEW Action: Fetch all registered devices for your web view.
        $result = $mysqli->query("SELECT device_id, connection_status, first_seen, last_seen FROM devices ORDER BY last_seen DESC;");
        $devices = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $devices[] = $row;
            }
        }
        echo json_encode($devices);
        break;

    case 'update_status':
        // NEW Action: Update a device's connection status from your web view.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'This action requires a POST request.']);
            break;
        }

        $input = is_array($jsonInput) ? $jsonInput : [];
        $deviceId = $input['deviceId'] ?? null;
        $status = $input['connectionStatus'] ?? null;

        if (!$deviceId || !in_array($status, ['allowed', 'denied'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Both deviceId and a valid connectionStatus (\'allowed\' or \'denied\') are required.']);
            break;
        }

        $stmt = $mysqli->prepare("UPDATE devices SET connection_status = ? WHERE device_id = ?");
        $stmt->bind_param("ss", $status, $deviceId);

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => "Device $deviceId status updated to $status."]);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to update device status.']);
        }
        $stmt->close();
        break;

    case 'update_account_status':
        // NEW Action: Update account active status from your web view.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'This action requires a POST request.']);
            break;
        }

        $input = is_array($jsonInput) ? $jsonInput : [];
        $accountId = $input['accountId'] ?? null;
        $isActive = $input['isActive'] ?? null;

        if (!$accountId || !is_bool($isActive)) {
            http_response_code(400);
            echo json_encode(['error' => 'Both accountId and isActive (boolean) are required.']);
            break;
        }

        $stmt = $mysqli->prepare("UPDATE accounts SET is_active = ? WHERE id = ?");
        $activeValue = $isActive ? 1 : 0;
        $stmt->bind_param("ii", $activeValue, $accountId);

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => "Account $accountId updated."]);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to update account status.']);
        }
        $stmt->close();
        break;

    case 'get_debug_logging':
        $enabled = $isDebugLoggingEnabled($mysqli);
        echo json_encode(['enabled' => $enabled]);
        break;

    case 'set_debug_logging':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'The set_debug_logging action requires a POST request.']);
            break;
        }

        $input = is_array($jsonInput) ? $jsonInput : [];
        $enabled = isset($input['enabled']) ? (bool)$input['enabled'] : null;
        if (!is_bool($enabled)) {
            http_response_code(400);
            echo json_encode(['error' => 'enabled (boolean) is required.']);
            break;
        }

        $value = $enabled ? '1' : '0';
        $stmt = $mysqli->prepare("UPDATE debug_settings SET value = ? WHERE `key` = 'enabled'");
        $stmt->bind_param("s", $value);
        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'enabled' => $enabled]);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to update debug logging setting.']);
        }
        $stmt->close();
        break;

    case 'get_logs':
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 200;
        if ($limit <= 0 || $limit > 500) {
            $limit = 200;
        }
        $stmt = $mysqli->prepare(
            "SELECT id, message, method, action, content_type, query_params, json_payload, raw_body, created_at " .
            "FROM debug_logs ORDER BY created_at DESC LIMIT ?"
        );
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        $logs = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $logs[] = $row;
            }
        }
        $stmt->close();
        echo json_encode($logs);
        break;

    default:
        // UPDATED: Added new actions to the error message.
        http_response_code(400); // Bad Request
        echo json_encode(['error' => "Unknown or missing action parameter. Available actions: 'ping', 'login', 'get_accounts', 'get_users', 'add_user', 'update_user', 'get_payments', 'sync_payments', 'get_devices', 'update_status', 'update_account_status', 'get_debug_logging', 'set_debug_logging', 'get_logs'."]);
        break;
}

// 5. --- CLEANUP ---
// Close the database connection.
$mysqli->close();
?>
