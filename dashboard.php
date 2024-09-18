<?php
include 'db.php';

session_start();

// Check if the user is logged in
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// Retrieve the current logged-in username
$username = $_SESSION['username'];

// Establish a database connection
$conn = getConnection();

// Query the user's ID
$stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$user_id = $user['id'];

// Query the user's held stocks, using encryption and decryption
$stmt = $conn->prepare("SELECT stock_symbol, quantity FROM user_stocks WHERE user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stocks_result = $stmt->get_result();

// Query the transaction history, using JOIN to directly fetch transaction records by username
$stmt = $conn->prepare("
    SELECT t.stock_symbol, t.quantity, t.trade_type, t.trade_time 
    FROM trades t 
    JOIN users u ON u.id = t.user_id 
    WHERE u.username = ?
");
$stmt->bind_param("s", $username);
$stmt->execute();
$trades_result = $stmt->get_result();

// Log an error if the query fails
if (!$trades_result) {
    error_log("Transaction history query error: " . $conn->error);
    die("System error, please try again later.");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        h1 {
            text-align: center;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table, th, td {
            border: 1px solid black;
        }
        th, td {
            padding: 10px;
            text-align: center;
        }
        th {
            background-color: #f2f2f2;
        }
        a.action-link {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #45a06b;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
        a.action-link:hover {
            background-color: #45a06b;
        }
        .no-records {
            text-align: center;
            color: red;
            font-weight: bold;
        }
        nav {
            background-color: #141414;
            padding: 10px;
            color: white;
        }
        nav a {
            color: white;
            margin-right: 20px;
            text-decoration: none;
        }
        nav a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>

<!-- Navigation bar -->
<nav>
    <a href="dashboard.php">Transaction History</a>
    <a href="trade.php">Make a Trade</a>
    <a href="logout.php">Logout</a>
</nav>

<h1>Held Stocks</h1>

<?php
if ($stocks_result->num_rows > 0) {
    echo "<table>";
    echo "<tr><th>Stock Symbol</th><th>Quantity</th></tr>";
    while ($row = $stocks_result->fetch_assoc()) {
        $encrypted_stock_symbol = $row['stock_symbol'];
        $stock_symbol = decryptData($encrypted_stock_symbol); // Decrypt stock symbol

        $quantity = $row['quantity'];

        echo "<tr>
                <td>" . htmlspecialchars($stock_symbol, ENT_QUOTES, 'UTF-8') . "</td>
                <td>" . htmlspecialchars($quantity, ENT_QUOTES, 'UTF-8') . "</td>
              </tr>";
    }
    echo "</table>";
} else {
    echo "<p class='no-records'>No stocks held</p>";
}
?>

<h1>Transaction History</h1>

<?php
if ($trades_result->num_rows > 0) {
    echo "<table>";
    echo "<tr><th>Stock Symbol</th><th>Quantity</th><th>Type</th><th>Transaction Time</th></tr>";
    while ($row = $trades_result->fetch_assoc()) {
        // Decrypt data
        $stock_symbol = htmlspecialchars(decryptData($row['stock_symbol']), ENT_QUOTES, 'UTF-8');
        $quantity = htmlspecialchars($row['quantity'], ENT_QUOTES, 'UTF-8');
        $trade_type = htmlspecialchars($row['trade_type'], ENT_QUOTES, 'UTF-8');
        $trade_time = htmlspecialchars($row['trade_time'], ENT_QUOTES, 'UTF-8');
        
        echo "<tr>
                <td>{$stock_symbol}</td>
                <td>{$quantity}</td>
                <td>{$trade_type}</td>
                <td>{$trade_time}</td>
              </tr>";
    }
    echo "</table>";
} else {
    echo "<p class='no-records'>No transaction records</p>";
}

// Close the database connection
$stmt->close();
?>

</body>
</html>
