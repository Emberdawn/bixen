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


// 3. --- ROUTING: DETERMINE THE ACTION ---
// We use a URL parameter '?action=...' to decide what to do.
$action = $_GET['action'] ?? ''; // Safely get the action, default to empty string.


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

        $input = json_decode(file_get_contents('php://input'), true);
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

        $passwordHash = password_hash($password, PASSWORD_BCRYPT);
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

        $input = json_decode(file_get_contents('php://input'), true);
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
            $passwordHash = password_hash($password, PASSWORD_BCRYPT);
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
        
        $json_input = file_get_contents('php://input');
        $payments_from_app = json_decode($json_input, true);
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

        $input = json_decode(file_get_contents('php://input'), true);
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

        $input = json_decode(file_get_contents('php://input'), true);
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

    case 'login':
        // Ensure the request is a POST request.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405); // Method Not Allowed
            echo json_encode(['status' => 'error', 'message' => 'This action requires a POST request.']);
            break;
        }

        // Decode the JSON input from the app.
        $input = json_decode(file_get_contents('php://input'), true);

        // Get the credentials from the input.
        $username = $input['username'] ?? null;
        $passwordHash = $input['passwordHash'] ?? null;

        // Check that credentials were provided.
        if (!$username || !$passwordHash) {
            http_response_code(400); // Bad Request
            echo json_encode(['status' => 'error', 'message' => 'Username and passwordHash are required.']);
            break;
        }

        // Look up the user in the database.
        $stmt = $mysqli->prepare("SELECT id, password_hash FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            
            // Compare the password hash from the app to the one in the database.
            if ($passwordHash === $user['password_hash']) {
                // SUCCESS: The password is correct.
                // Return a 'success' status and the user's ID.
                echo json_encode([
                    'status' => 'success', 
                    'userId' => (int)$user['id']
                ]);
            } else {
                // FAILURE: The password is incorrect.
                // Return an 'error' status and a message.
                echo json_encode(['status' => 'error', 'message' => 'Invalid username or password.']);
            }
        } else {
            // FAILURE: The user was not found.
            // Return an 'error' status and a message.
            echo json_encode(['status' => 'error', 'message' => 'Invalid username or password.']);
        }
        $stmt->close();
        break;

    default:
        // UPDATED: Added new actions to the error message.
        http_response_code(400); // Bad Request
        echo json_encode(['error' => "Unknown or missing action parameter. Available actions: 'ping', 'get_accounts', 'get_users', 'add_user', 'update_user', 'get_payments', 'sync_payments', 'get_devices', 'update_status', 'update_account_status', 'login'."]);
        break;
}

// 5. --- CLEANUP ---
// Close the database connection.
$mysqli->close();
?>
