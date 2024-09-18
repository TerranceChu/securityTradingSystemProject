<?php
session_start();

// 檢查是否存在會話
if (isset($_SESSION['username'])) {
    // 記錄登出事件
    $username = $_SESSION['username'];
    $user_ip = $_SERVER['REMOTE_ADDR'];
    $timestamp = date("Y-m-d H:i:s");
    error_log("用戶 $username 已登出，IP: $user_ip，時間: $timestamp");

    // 清除會話數據
    session_unset();
    session_destroy();

    // 重新啟動會話，並生成一個新的會話ID來防止會話固定攻擊
    session_start();
    session_regenerate_id(true);

    // 清除所有快取，防止回退攻擊
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Pragma: no-cache"); // 用於防止舊版本的瀏覽器快取
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT"); // 過期時間設置為過去

    // 重定向到登錄頁面
    header("Location: login.php");
    exit;
} else {
    // 如果用戶未登錄，直接重定向到登錄頁面
    header("Location: login.php");
    exit;
}
?>
