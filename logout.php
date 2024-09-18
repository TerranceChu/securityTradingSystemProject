<?php
session_start();

// Check if session exists
if (isset($_SESSION['username'])) {
    // Log the logout event
    $username = $_SESSION['username'];
    $user_ip = $_SERVER['REMOTE_ADDR'];
    $timestamp = date("Y-m-d H:i:s");
    error_log("User $username has logged out, IP: $user_ip, Time: $timestamp");

    // Clear session data
    session_unset();
    session_destroy();

    // Restart session and regenerate session ID to prevent session fixation attacks
    session_start();
    session_regenerate_id(true);

    // Clear all caches to prevent back button attacks
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Pragma: no-cache"); // Used to prevent caching in older browsers
    header("Expires: Sat, 21 Jul 2000 05:00:00 GMT"); // Set expiration date to the past

    // Redirect to the login page
    header("Location: login.php");
    exit;
} else {
    // If the user is not logged in, redirect to the login page
    header("Location: login.php");
    exit;
}
?>
