<?php
require_once "config.php";

$username = $password = $confirm_password = $email = "";
$username_err = $password_err = $confirm_password_err = $email_err = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    if (empty(trim($_POST["username"]))) {
        $username_err = "Please enter a username.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["username"]))) {
        $username_err = "Username can only contain letters, numbers, and underscores.";
    } else {
        $sql = "SELECT id FROM users WHERE username = ?";

        $params = array(trim($_POST["username"]);
        $stmt = sqlsrv_query($conn, $sql, $params);

        if (sqlsrv_num_rows($stmt) == 1) {
            $username_err = "This username is already taken.";
        } else {
            $username = trim($_POST["username"]);
        }
    }

    if (empty(trim($_POST["email"]))) {
        $email_err = "Please enter an email.";
    } else {
        $email = trim($_POST["email"]);
    }

    if (empty(trim($_POST["password"]))) {
        $password_err = "Please enter a password.";
    } elseif (strlen(trim($_POST["password"])) < 6) {
        $password_err = "Password must have at least 6 characters.";
    } else {
        $password = trim($_POST["password"]);
    }

    if (empty(trim($_POST["confirm_password"])) || ($password != trim($_POST["confirm_password"]))) {
        $confirm_password_err = "Password did not match.";
    }

    if (empty($username_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)) {

        $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        $params = array($username, $email, password_hash($password, PASSWORD_DEFAULT));

        $stmt = sqlsrv_query($conn, $sql, $params);

        if ($stmt) {
            header("location: login.php");
        } else {
            echo "Oops! Something went wrong. Please try again later.";
        }
    }

    sqlsrv_close($conn);
}
?>
