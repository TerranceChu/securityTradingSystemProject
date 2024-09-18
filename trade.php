<?php
include 'db.php';

session_start();

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// If the CSRF Token has not been generated, create one
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = ''; // Initialize error message variable

try {
    $conn = getConnection(); // Get global database connection

    if ($_SERVER["REQUEST_METHOD"] == "POST") {

        // 1. Check the CSRF Token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = "CSRF Token validation failed";
        }

        // 2. Validate the stock symbol
        elseif (!preg_match("/^[A-Z]{1,5}$/", $_POST['stock_symbol'])) {
            $error = "Invalid stock symbol";
        }

        // 3. Validate the quantity
        elseif (!is_numeric($_POST['quantity']) || $_POST['quantity'] <= 0 || intval($_POST['quantity']) != $_POST['quantity']) {
            $error = "Invalid quantity, must be a positive integer";
        }

        // 4. Validate the trade type
        elseif (!in_array($_POST['trade_type'], ['buy', 'sell'])) {
            $error = "Invalid trade type";
        }

        if (empty($error)) {
            // Query for the user's ID
            $username = $_SESSION['username'];
            $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                $user_id = $row['id'];

                // Convert stock symbol to uppercase and trim it
                $stock_symbol = strtoupper(trim($_POST['stock_symbol']));
                $quantity = intval($_POST['quantity']); // Convert quantity to integer
                
                // Debug quantity to ensure it's correct before encryption
                echo "Original quantity (before encryption): " . $quantity . "<br>";

                $trade_type = $_POST['trade_type'];

                // Validate stock quantity before processing a sell operation
                if ($trade_type === 'sell') {
                    // Query the stock quantity owned by the user
                    $stmt = $conn->prepare("SELECT quantity FROM user_stocks WHERE user_id = ? AND stock_symbol = ?");
                    $stmt->bind_param("is", $user_id, $stock_symbol);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    $row = $result->fetch_assoc();

                    $current_quantity = $row['quantity'] ?? 0;

                    if ($current_quantity < $quantity) {
                        $error = "Sell failed: insufficient stock quantity";
                    }
                }

                if (empty($error)) {
                    // Encrypt stock symbol and quantity
                    $encrypted_symbol = encryptData($stock_symbol);
                    $quantity = intval($_POST['quantity']); // Keep quantity as a number, no encryption

                    // Insert the trade record
                    $stmt = $conn->prepare("INSERT INTO trades (user_id, stock_symbol, quantity, trade_type) VALUES (?, ?, ?, ?)");
                    $stmt->bind_param("ssis", $user_id, $encrypted_symbol, $quantity, $trade_type);

                    if ($stmt->execute()) {
                        // Update user_stocks table based on the trade type
                        if ($trade_type === 'buy') {
                            $stmt = $conn->prepare("INSERT INTO user_stocks (user_id, stock_symbol, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?");
                            $stmt->bind_param("issi", $user_id, $encrypted_symbol, $quantity, $quantity);
                        } else if ($trade_type === 'sell') {
                            $stmt = $conn->prepare("UPDATE user_stocks SET quantity = quantity - ? WHERE user_id = ? AND stock_symbol = ?");
                            $stmt->bind_param("iis", $quantity, $user_id, $stock_symbol);
                        }

                        if ($stmt->execute()) {
                            // After successful trade, regenerate CSRF Token
                            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                            // Clear form data
                            $_POST['stock_symbol'] = '';
                            $_POST['quantity'] = '';
                            $_POST['trade_type'] = 'buy'; // Default to "buy"

                            // Log the successful trade
                            error_log("User $username successfully executed a trade: $trade_type $quantity $stock_symbol");

                            // Redirect to prevent form resubmission
                            header("Location: trade.php?success=true");
                            exit;
                        } else {
                            $error = "Error updating stock record: " . $stmt->error;
                        }
                    } else {
                        $error = "Error processing trade: " . $stmt->error;
                    }
                }

                $stmt->close();
            } else {
                $error = "User not found, please log in again";
            }
        }

    }
} catch (Exception $e) {
    $error = "System error: " . $e->getMessage();
    error_log("Trade system error: " . $e->getMessage());
}
?>
<nav style="background-color: #333; padding: 10px; color: white;">
    <a href="dashboard.php" style="color: white; margin-right: 20px; text-decoration: none;">Trade History</a>
    <a href="trade.php" style="color: white; margin-right: 20px; text-decoration: none;">Make a Trade</a>
    <a href="logout.php" style="color: white; text-decoration: none;">Logout</a>
</nav>

<!-- Stock code table -->
<h2>Popular Stock Codes</h2>
<table border="1" cellpadding="10" cellspacing="0" style="width: 100%; text-align: center;">
    <tr>
        <th>Stock Name</th>
        <th>Stock Code</th>
    </tr>
    <tr>
        <td>Apple</td>
        <td>AAPL</td>
    </tr>
    <tr>
        <td>Google</td>
        <td>GOOGL</td>
    </tr>
    <tr>
        <td>Amazon</td>
        <td>AMZN</td>
    </tr>
    <tr>
        <td>Microsoft</td>
        <td>MSFT</td>
    </tr>
    <tr>
        <td>Tesla</td>
        <td>TSLA</td>
    </tr>
</table>

<!-- Trade form -->
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    Stock Symbol: <input type="text" name="stock_symbol" value="<?php echo htmlspecialchars($_POST['stock_symbol'] ?? '', ENT_QUOTES); ?>" required><br>
    Quantity: <input type="number" name="quantity" value="<?php echo htmlspecialchars($_POST['quantity'] ?? '', ENT_QUOTES); ?>" required><br>
    Trade Type: <select name="trade_type">
        <option value="buy" <?php echo ($_POST['trade_type'] ?? '') == 'buy' ? 'selected' : ''; ?>>Buy</option>
        <option value="sell" <?php echo ($_POST['trade_type'] ?? '') == 'sell' ? 'selected' : ''; ?>>Sell</option>
    </select><br>
    <button type="submit">Submit Trade</button>
</form>

<?php if (!empty($error)): ?>
    <div style="color: red; border: 1px solid red; padding: 5px;">
        <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
    </div>
<?php endif; ?>

<?php if (isset($_GET['success']) && $_GET['success'] == 'true'): ?>
    <div style="color: green; border: 1px solid green; padding: 5px;">
        Trade successfully submitted.
    </div>
<?php endif; ?>
