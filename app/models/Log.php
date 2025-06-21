<?php
class Log {

    private $db;

    public function __construct() {
        $this->db = db_connect();
    }

    public function logAttempt($username, $status) {
        $query = "INSERT INTO login_logs (username, status) VALUES (:username, :status)";
        $stmt = $this->db->prepare($query);
        $stmt->bindValue(':username', $username);
        $stmt->bindValue(':status', $status);
        $stmt->execute();
    }

    public function getRecentFailures($username) {
        $query = "SELECT * FROM login_logs WHERE username = :username AND status = 'bad' ORDER BY time DESC LIMIT 3";
        $stmt = $this->db->prepare($query);
        $stmt->bindValue(':username', $username);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
