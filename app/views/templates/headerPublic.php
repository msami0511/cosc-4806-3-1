    <?php
    if (isset($_SESSION['auth']) == 1) {
        header('Location: /home');
    }
    ?>

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link rel="icon" href="/favicon.png">
        <title>COSC 4806</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="mobile-web-app-capable" content="yes">

        <!-- Custom CSS (Bootstrap removed) -->
        <link rel="stylesheet" href="/public/css/style.css">
    </head>
    <body>
