<?php

class Login extends Controller {

		public function index() {
				$this->view('login/index');
		}

		public function verify() {
				$username = strtolower($_POST['username'] ?? '');
				$password = $_POST['password'] ?? '';

				$logModel = $this->model('Log');

				// Check last 3 failed attempts
				$failures = $logModel->getRecentFailures($username);
				if (count($failures) === 3) {
						$lastTime = strtotime($failures[0]['time']);
						if (time() - $lastTime < 60) {
								$error = "Too many failed attempts. Please wait 60 seconds.";
								$this->view('login/index', ['error' => $error]);
								return;
						}
				}

				$userModel = $this->model('User');
				$user = $userModel->getUserByUsername($username);

				if (!$user || !password_verify($password, $user['password'])) {
						// Log bad attempt
						$logModel->logAttempt($username, 'bad');

						$error = "Invalid username or password.";
						$this->view('login/index', ['error' => $error]);
						return;
				}

				// Log good attempt
				$logModel->logAttempt($username, 'good');

				$_SESSION['auth'] = 1;
				$_SESSION['username'] = $username;
				header("Location: /home");
				exit();
		}
}
