<?php

class App {

    protected $controller = 'login';
    protected $method = 'index';
    protected $special_url = ['apply'];
    protected $params = [];

    public function __construct() {
        if (isset($_SESSION['auth']) && $_SESSION['auth'] == 1) {
            $this->controller = 'home';
        }

        $url = $this->parseUrl();

        // Check if controller is specified and file exists
        if (isset($url[0]) && file_exists('app/controllers/' . $url[0] . '.php')) {
            $this->controller = $url[0];
            $_SESSION['controller'] = $this->controller;

            if (in_array($this->controller, $this->special_url)) {
                $this->method = 'index';
            }
            unset($url[0]);
        }
        // No else redirect here; just use default controller if none specified

        require_once 'app/controllers/' . $this->controller . '.php';

        $this->controller = new $this->controller;

        // Check if method is specified and exists
        if (isset($url[1]) && method_exists($this->controller, $url[1])) {
            $this->method = $url[1];
            $_SESSION['method'] = $this->method;
            unset($url[1]);
        }

        // Rebase params to zero-based array if exist
        $this->params = $url ? array_values($url) : [];

        call_user_func_array([$this->controller, $this->method], $this->params);
    }

    public function parseUrl() {
        $u = $_SERVER['REQUEST_URI'];
        $url = explode('/', filter_var(rtrim($u, '/'), FILTER_SANITIZE_URL));
        // Remove the first empty element caused by leading slash
        if (empty($url[0])) {
            array_shift($url);
        }
        return $url;
    }
}
