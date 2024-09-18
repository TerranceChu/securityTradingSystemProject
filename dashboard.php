<?php
session_start();

// 檢查用戶是否已登錄
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// 引入數據庫連接函數
include 'db.php';

// 獲取當前登錄用戶的用戶名
$username = $_SESSION['username'];

// 建立數據庫連接
$conn = getConnection();

// 查詢交易歷史，使用 JOIN 來直接從用戶名查詢交易記錄
$stmt = $conn->prepare("
    SELECT t.stock_symbol, t.quantity, t.trade_type, t.trade_time 
    FROM trades t 
    JOIN users u ON u.id = t.user_id 
    WHERE u.username = ?
");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

// 如果查詢失敗，記錄錯誤
if (!$result) {
    error_log("交易歷史查詢錯誤: " . $conn->error);
    die("系統錯誤，請稍後再試。");
}
?>

<!DOCTYPE html>
<html lang="zh-HK">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>交易歷史記錄</title>
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
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
        a.action-link:hover {
            background-color: #45a049;
        }
        .no-records {
            text-align: center;
            color: red;
            font-weight: bold;
        }
        nav {
            background-color: #333;
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

<!-- 導航欄 -->
<nav>
    <a href="dashboard.php">交易歷史記錄</a>
    <a href="trade.php">進行交易</a>
    <a href="logout.php">登出</a>
</nav>

<h1>交易歷史記錄</h1>

<?php
if ($result->num_rows > 0) {
    // 以表格形式顯示交易歷史
    echo "<table>";
    echo "<tr><th>股票代碼</th><th>數量</th><th>類型</th><th>交易時間</th></tr>";
    while ($row = $result->fetch_assoc()) {
        // 防止XSS攻擊
        $stock_symbol = htmlspecialchars($row['stock_symbol'], ENT_QUOTES, 'UTF-8');
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
    echo "<p class='no-records'>暫無交易記錄</p>";
}

// 關閉數據庫連接
$stmt->close();
?>

</body>
</html>
