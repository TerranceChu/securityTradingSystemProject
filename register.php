<?php
include 'db.php';

session_start();

// Initialize error variable
$error = '';

// If CSRF Token doesn't exist, generate a new one
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Initialize $username and $password variables
    $username = isset($_POST['username']) ? trim($_POST['username']) : ''; 
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';

    // Check CSRF Token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "CSRF Token verification failed";
    } else {
        // Check username and password
        if (empty($username) || empty($password)) {
            $error = "Username and password are required";
        }
        // Password strength check
        elseif (strlen($password) < 8 || !preg_match("/[A-Z]/", $password) || !preg_match("/[0-9]/", $password)) {
            $error = "Password must be at least 8 characters long, include one uppercase letter and one number";
        } else {
            // Check if username already exists
            $conn = getConnection(); // Get database connection
            $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $error = "Username already exists, please choose another";
                error_log("Attempt to use existing username $username, time: " . date("Y-m-d H:i:s") . ", IP: " . $_SERVER['REMOTE_ADDR']);
            } else {
                // If username doesn't exist, insert new user
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $role = "user"; // Default role

                $stmt = $conn->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
                $stmt->bind_param("sss", $username, $hashed_password, $role);

                if ($stmt->execute()) {
                    // Registration successful, log event and redirect to login page
                    error_log("New user registration successful: $username, time: " . date("Y-m-d H:i:s") . ", IP: " . $_SERVER['REMOTE_ADDR']);
                    
                    // Prevent session fixation attack
                    session_regenerate_id(true);
                    
                    // Redirect to login page
                    header("Location: login.php");
                    exit;
                } else {
                    $error = "Error occurred during registration: " . $stmt->error;
                    error_log("Error during registration: " . $stmt->error);
                }
            }

            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <style>
        /* Simple form styles */
        form {
            margin: 20px;
        }
        label, input, button {
            display: block;
            margin: 10px 0;
        }
        button:hover {
            background-color: #45a049;
        }
        .error {
            color: red;
            border: 1px solid red;
            padding: 5px;
        }
        .login-btn:hover {
            background-color: #007B9E;
        }
    </style>
    <script>
        // Password strength check
        function validatePassword() {
            const password = document.getElementById("password").value;
            const strengthText = document.getElementById("strengthText");

            const hasUppercase = /[A-Z]/.test(password);
            const hasNumber = /\d/.test(password);
            const hasMinLength = password.length >= 8;

            if (hasUppercase && hasNumber && hasMinLength) {
                strengthText.textContent = "Password strength: Strong";
                strengthText.style.color = "green";
            } else {
                strengthText.textContent = "Password must be at least 8 characters long, include one uppercase letter and one number";
                strengthText.style.color = "red";
            }
        }
    </script>
</head>
<body>

<h1>Register a New Account</h1>

<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    
    <label for="username">Username:</label>
    <input type="text" name="username" pattern="[A-Za-z0-9]{5,}" title="Username must be at least 5 letters or numbers" required><br>
    
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" oninput="validatePassword()" required>
    <small id="strengthText" style="color: red;">Password must be at least 8 characters long, include one uppercase letter and one number</small><br>
    
    <button type="submit">Register</button>
</form>

<?php if (!empty($error)): ?>
    <div class="error">
        <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?> <!-- Prevent XSS -->
    </div>
<?php endif; ?>

<!-- Login button -->
<a href="login.php" class="login-btn">Already have an account? Click here to log in</a>

</body>
</html>
