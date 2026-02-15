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

// FIXED: 'users' table now uses 'username' and matches the expected role default.
$tableStatements = [
    "CREATE TABLE IF NOT EXISTS accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        sort_order INT NOT NULL DEFAULT 0
    )",
    "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user'
    )",
    "CREATE TABLE IF NOT EXISTS payments (
        server_id INT AUTO_INCREMENT PRIMARY KEY,
        account_id INT NOT NULL,
        user_id INT NOT NULL,
        amount INT NOT NULL,
        `timestamp` DATETIME NOT NULL,
        local_id BIGINT,
        FOREIGN KEY (account_id) REFERENCES accounts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )",
    "CREATE TABLE IF NOT EXISTS devices (
        device_id VARCHAR(255) PRIMARY KEY,
        connection_status VARCHAR(50) NOT NULL DEFAULT 'allowed',
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )",
];

foreach ($tableStatements as $statement) {
    if (!$mysqli->query($statement)) {
        http_response_code(500);
        echo json_encode([
            'error' => 'Failed to initialize database tables: ' . $mysqli->error,
            'statement' => $statement
        ]);
        exit();
    }
}


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
        $username = $input['username'] ?? null; // App might still send 'username' from a login form
        $password = $input['password'] ?? null;

        if (!$username || !$password) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Username and password are required.']);
            break;
        }

        // FIXED: Query by 'username'.
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
        // Action: Fetch all accounts.
        $accounts = [];

        $sql = "SELECT id, name, is_active AS active, sort_order AS sortOrder " .
            "FROM accounts " .
            "WHERE is_active = TRUE " .
            "ORDER BY sort_order ASC";
        $result = $mysqli->query($sql);

        if (!$result) {
            http_response_code(500);
            echo json_encode(['error' => 'Database query failed.']);
            break;
        }

        while ($row = $result->fetch_assoc()) {
            $row['id'] = (int)$row['id'];
            $row['active'] = (bool)$row['active'];
            $row['sortOrder'] = (int)$row['sortOrder'];
            $accounts[] = $row;
        }

        echo json_encode($accounts);
        break;

    case 'get_users':
        // FIXED: Select 'username' and return it correctly.
        $result = $mysqli->query("SELECT id, username, role FROM users;");
        $users = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $users[] = [
                    'id' => (int)$row['id'],
                    'username' => $row['username'],
                    'role' => $row['role'],
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
        $username = trim($input['username'] ?? $input['name'] ?? ''); // accept legacy "name"
        $password = $input['password'] ?? '';
        $role = $input['role'] ?? 'cashier'; // FIXED: better default
        if ($role === 'user') {
            $role = 'cashier';
        }

        if ($username === '' || $password === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Username and password are required.']);
            break;
        }

        if (!in_array($role, ['cashier', 'admin'], true)) { // FIXED: align with app
            http_response_code(400);
            echo json_encode(['error' => 'Role must be either cashier or admin.']);
            break;
        }

        $passwordHash = $normalizePasswordHash($password);
        // FIXED: Insert into 'username' column
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
        $username = trim($input['username'] ?? $input['name'] ?? ''); // accept legacy "name"
        $password = $input['password'] ?? '';
        $role = $input['role'] ?? 'cashier'; // FIXED: better default
        if ($role === 'user') {
            $role = 'cashier';
        }

        if ($userId <= 0 || $username === '') {
            http_response_code(400);
            echo json_encode(['error' => 'User id and username are required.']);
            break;
        }

        if (!in_array($role, ['cashier', 'admin'], true)) { // FIXED: align with app
            http_response_code(400);
            echo json_encode(['error' => 'Role must be either cashier or admin.']);
            break;
        }

        if ($password !== '') {
            $passwordHash = $normalizePasswordHash($password);
            // FIXED: Update 'username' column
            $stmt = $mysqli->prepare("UPDATE users SET username = ?, role = ?, password_hash = ? WHERE id = ?");
            $stmt->bind_param("sssi", $username, $role, $passwordHash, $userId);
        } else {
            // FIXED: Update 'username' column
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
        // FIXED: Select users.username instead of users.name
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
        $paymentsJson = json_encode($payments);

        // Save the get_payments reply to a .txt file for debugging/auditing.
        $logDir = __DIR__ . '/logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0775, true);
        }
        file_put_contents($logDir . '/get_payments_reply.txt', $paymentsJson . PHP_EOL);

        echo $paymentsJson;
        break;

    case 'sync_payments':
        // FIXED: This was the source of the 500 error.
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
                if (!is_array($payment)) {
                    $sync_results[] = ['status' => 'error', 'message' => 'Invalid payment payload.'];
                    continue;
                }

                // Accept snake_case and camelCase to avoid crashing on mixed client versions.
                $localId = $payment['id'] ?? $payment['local_id'] ?? null;
                $accountId = $payment['account_id'] ?? $payment['accountId'] ?? null;
                $userId = $payment['user_id'] ?? $payment['userId'] ?? null;
                $amount = $payment['amount'] ?? null;
                $rawTimestamp = $payment['timestamp'] ?? null;

                if ($localId === null || $accountId === null || $userId === null || $amount === null || $rawTimestamp === null) {
                    $sync_results[] = [
                        'localId' => $localId !== null ? (int)$localId : null,
                        'status' => 'error',
                        'message' => 'Missing required fields: id/local_id, account_id/accountId, user_id/userId, amount, timestamp.'
                    ];
                    continue;
                }

                // Ensure numeric types and convert milliseconds to seconds explicitly to prevent float->int deprecation warnings.
                $localId = (int)$localId;
                $accountId = (int)$accountId;
                $userId = (int)$userId;
                $amount = (int)$amount;
                $timestampMs = (int)round((float)$rawTimestamp);
                $timestampSeconds = intdiv($timestampMs, 1000);
                $datetime = date("Y-m-d H:i:s", $timestampSeconds);

                $stmt->bind_param("iiiis", $localId, $accountId, $userId, $amount, $datetime);
                if ($stmt->execute()) {
                    $sync_results[] = [
                        'localId' => $localId,
                        'serverId' => (int)$mysqli->insert_id,
                        'status' => 'success'
                    ];
                } else {
                    $sync_results[] = [
                        'localId' => $localId,
                        'status' => 'error',
                        'message' => $stmt->error
                    ];
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

    default:
        // UPDATED: Added new actions to the error message.
        http_response_code(400); // Bad Request
        echo json_encode(['error' => "Unknown or missing action parameter. Available actions: 'ping', 'login', 'get_accounts', 'add_account', 'get_users', 'add_user', 'update_user', 'get_payments', 'sync_payments', 'get_devices', 'update_status', 'update_account_status'."]);
        break;
}

// 5. --- CLEANUP ---
// Close the database connection.
$mysqli->close();
?>
