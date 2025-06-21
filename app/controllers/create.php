<?php

class Create extends Controller {

    public function index() {
        $this->view('create/index');
    }

    public function createAccount() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = $_POST['username'];
            $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

            $userModel = $this->model('User');
            if ($userModel->findUserByUsername($username)) {
                $error = "Username already exists.";
                $this->view('create/index', ['error' => $error]);
                return;
            }

            $userModel->createUser($username, $password);
            header("Location: /login");
        }
    }
}
