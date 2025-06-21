<?php
if (!isset($_SESSION['auth'])) {
    header('Location: /login');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>COSC 4806</title>
    <link rel="icon" href="/favicon.png" />
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0; padding: 0;
            background: #f0f0f0;
        }
        nav {
            background-color: #004080;
            padding: 10px 20px;
        }
        nav .brand {
            color: white;
            font-weight: bold;
            font-size: 1.5em;
            text-decoration: none;
            margin-right: 20px;
        }
        nav a {
            color: white;
            text-decoration: none;
            margin-right: 15px;
            font-weight: bold;
        }
        nav a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
<nav>
    <a href="#" class="brand">COSC 4806</a>
    <a href="/home">Home</a>
    <a href="/about">About Me</a>
    <a href="/logout">Logout</a>
</nav>
