<?php require_once 'app/views/templates/headerPublic.php' ?>

<main role="main" class="container">
    <div class="page-header" id="banner">
        <h1>Create Account</h1>
    </div>

    <?php if (!empty($data['error'])): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($data['error']) ?></div>
    <?php endif; ?>

    <form action="/create/createAccount" method="post">
        <div class="form-group">
            <label for="username">Username</label>
            <input required type="text" name="username" id="username" class="form-control">
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input required type="password" name="password" id="password" class="form-control">
        </div>

        <br>
        <button type="submit" class="btn btn-primary">Register</button>
    </form>

    <p class="mt-3">Already have an account? <a href="/login">Login here</a></p>
</main>

<?php require_once 'app/views/templates/footer.php' ?>
