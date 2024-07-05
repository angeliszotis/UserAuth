<?php
/*
 * testing composer
 */
namespace AngelisZotis\UserAuth;

use MongoDB\Client;

class Auth {
    private $client;
    private $collection;
    private $pepper;

    public function __construct($mongoUri, $database, $pepper) {
        $this->client = new Client($mongoUri);
        $this->collection = $this->client->$database->users;
        $this->pepper = $pepper;
    }

    public function register($username, $password) {
        $salt = bin2hex(random_bytes(16));
        $pepperedPassword = $password . $this->pepper;
        $hashedPassword = password_hash($pepperedPassword, PASSWORD_BCRYPT, ['cost' => 12]);

        $result = $this->collection->insertOne([
            'username' => $username,
            'hashed_password' => $hashedPassword,
            'salt' => $salt
        ]);

        return $result->getInsertedCount() === 1;
    }

    public function login($username, $password) {
        $user = $this->collection->findOne(['username' => $username]);

        if ($user) {
            $pepperedPassword = $password . $this->pepper;

            if (password_verify($pepperedPassword, $user['hashed_password'])) {
                return true;
            }
        }

        return false;
    }
}
