<?php
include 'db.php';

session_start();

$error = ''; // Initialize the error message variable
$login_block_time = 300; // Set a 5-minute lockout time

// Initialize CSRF Token (if it doesn't exist)
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Initialize login attempts and time (if they don't exist)
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt_time'] = time();
}

// Check if there are more than 5 failed login attempts and set a time limit
if ($_SESSION['login_attempts'] >= 5) {
    $time_diff = time() - $_SESSION['last_attempt_time'];
    if ($time_diff < $login_block_time) {
        $remaining_time = $login_block_time - $time_diff;
        $error = "Too many login attempts, please try again later. Remaining time: " . ceil($remaining_time / 60) . " minutes";
        // Log the event of too many login attempts
        error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} User $username had too many failed login attempts, lockout remaining time: " . ceil($remaining_time / 60) . " minutes");
    } else {
        // Reset login attempts if the lockout time has passed
        $_SESSION['login_attempts'] = 0;
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && empty($error)) {
    // Check CSRF Token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "CSRF Token validation failed";
        error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} CSRF Token validation failed");
    } else {
        // Sanitize input
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        // Check if the username and password were entered
        if (empty($username) || empty($password)) {
            $error = "Please enter both username and password";
        } else {
            // Use prepared statements to prevent SQL injection
            $conn = getConnection(); // Get database connection
            $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                // Verify password
                if (password_verify($password, $row['password'])) {
                    // Prevent session fixation attack
                    session_regenerate_id(true);
                    $_SESSION['username'] = $username;
                    $_SESSION['role'] = $row['role'];

                    // Reset login attempts
                    $_SESSION['login_attempts'] = 0;
                    $_SESSION['last_attempt_time'] = time();

                    // Log successful login
                    error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} User $username logged in successfully");

                    // Redirect to dashboard
                    header("Location: dashboard.php");
                    exit;
                } else {
                    $error = "Incorrect password, please try again";
                    $_SESSION['login_attempts']++; // Increment failed login attempts
                    $_SESSION['last_attempt_time'] = time(); // Set the time of the last attempt
                    // Log failed login attempt
                    error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} User $username entered the wrong password");
                }
            } else {
                $error = "Username does not exist";
                // Log the error
                error_log("[" . date("Y-m-d H:i:s") . "] IP: {$_SERVER['REMOTE_ADDR']} Attempted username $username does not exist");
            }

            $stmt->close();
        }
    }
}
?>

<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    
    <label for="username">Username:</label>
    <input type="text" name="username" id="username" required><br>

    <label for="password">Password:</label>
    <input type="password" name="password" id="password" required><br>

    <button type="submit">Login</button>
</form>

<?php if (!empty($error)): ?>
    <div style="color: red; border: 1px solid red; padding: 5px;">
        <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?> <!-- Prevent XSS attacks -->
    </div>
<?php endif; ?>

<!-- Register button -->
<div style="margin-top: 20px;">
    <p>Don't have an account? <a href="register.php">Click here to register</a></p>
</div>
