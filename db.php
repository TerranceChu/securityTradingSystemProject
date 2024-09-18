<?php
// Global connection variable
$global_conn = null;
$encryption_key = base64_decode('aovPWMLHmOZJ1UxjpglogXm7a9DtkzA6MQws1Hjn9QU='); // Use Base64 encoded encryption key
$iv = base64_decode('ycCzJWI1AtVxFEjO1+n7hw==');

// Modify the encryption function, base64 encode the encrypted data
function encryptData($data) {
    global $encryption_key, $iv;

    // Check if the encryption result was successful
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $encryption_key, 0, $iv);
    if ($encrypted === false) {
        // Log the error message
        error_log("Encryption failed: " . openssl_error_string());
        return null;
    }

    // Use base64 encoding to store in the database
    return base64_encode($encrypted);
}

function decryptData($data) {
    global $encryption_key, $iv;

    // Base64 decode
    $decoded_data = base64_decode($data);
    if ($decoded_data === false) {
        error_log("Base64 decoding failed");
        return null;
    }

    // Decrypt data
    $decrypted = openssl_decrypt($decoded_data, 'aes-256-cbc', $encryption_key, 0, $iv);
    if ($decrypted === false) {
        // Log the error message
        error_log("Decryption failed: " . openssl_error_string());
        return null;
    }

    return $decrypted;
}

// Set session security configurations
ini_set('session.cookie_httponly', 1); // Prevent JavaScript from accessing cookies
ini_set('session.cookie_secure', 1);    // Only allow cookies to be transmitted over HTTPS

function getConnection() {
    global $global_conn;

    // If no connection is established yet, create one
    if ($global_conn === null) {
        $config = include 'D:/xampp/config/config.php';
        $servername = $config['db_host'];
        $username = $config['db_user'];
        $password = $config['db_pass'];
        $dbname = $config['db_name'];

        // Create connection
        $global_conn = new mysqli($servername, $username, $password, $dbname);

        // Get the current time and user's IP address for logging purposes
        $timestamp = date("Y-m-d H:i:s");
        $user_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        // Check if the connection was successful
        if ($global_conn->connect_error) {
            // Log the error to a file instead of showing technical details to the user
            $error_message = "[$timestamp] [IP: $user_ip] Connection failed: " . $global_conn->connect_error;
            error_log($error_message, 3, __DIR__ . "/error_log.txt");
            die("Database connection failed, please try again later.");
        }

        // Set character set to prevent database encoding issues
        if (!$global_conn->set_charset("utf8mb4")) {
            $error_message = "[$timestamp] [IP: $user_ip] Charset setting failed: " . $global_conn->error;
            error_log($error_message, 3, __DIR__ . "/error_log.txt");
            die("Charset setting failed, please try again later.");
        }

        // Log successful connection
        $success_message = "[$timestamp] [IP: $user_ip] Successfully connected to the database";
        error_log($success_message, 3, __DIR__ . "/error_log.txt");
    }

    // Return the global connection
    return $global_conn;
}

// Automatically close the connection at the end of the script
register_shutdown_function(function() {
    global $global_conn;
    if ($global_conn !== null) {
        $timestamp = date("Y-m-d H:i:s");
        $user_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        error_log("[$timestamp] [IP: $user_ip] Closing database connection", 3, __DIR__ . "/error_log.txt");
        $global_conn->close();
        $global_conn = null; // Ensure the connection is set to null to prevent duplicate closures
    }
});
?>
