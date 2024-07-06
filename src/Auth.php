<?php
namespace AngelisZotis\UserAuth;

use MongoDB\Client;
use MongoDB\BSON\UTCDateTime;

class UserAuth
{
    private $collection;
    private string $pepper;

    public function __construct(string $mongoUri, string $dbName, string $collectionName, string $pepper)
    {
        $mongoClient = new Client($mongoUri);
        $database = $mongoClient->selectDatabase($dbName);
        $this->collection = $database->selectCollection($collectionName);
        $this->pepper = $pepper;
    }

    public function registerUser(string $username, string $password): bool
    {
        // Check if the username already exists
        if ($this->collection->countDocuments(['username' => $username]) > 0) {
            return false; // Username already taken
        }

        // Generate salt for password hashing
        $salt = $this->generateSalt();

        // Hash the password with pepper, salt, and bcrypt
        $hashedPassword = password_hash($this->pepper . $salt . $password, PASSWORD_BCRYPT);

        // Store username, hashed password, and salt in MongoDB
        $this->collection->insertOne([
            'username' => $username,
            'hashed_password' => $hashedPassword,
            'salt' => $salt
        ]);

        return true; // User registered successfully
    }

    public function loginUser(string $username, string $password): ?string
    {
        // Find the user by username
        $user = $this->collection->findOne(['username' => $username]);

        if (!$user) {
            return null; // User not found
        }

        // Validate the password
        $hashedPassword = $user['hashed_password'];
        $salt = $user['salt'];

        // Introduce a delay of 5 milliseconds to defend against timing attacks
        usleep(5000); // 5000 microseconds = 5 milliseconds

        if (password_verify($this->pepper . $salt . $password, $hashedPassword)) {
            // Password is correct, generate and return a token
            $userId = (string) $user['_id']; // Assuming MongoDB's ObjectId
            return $this->generateToken($userId);
        }

        return null; // Incorrect password
    }

    public function generateToken(string $userId): string
    {
        $salt = $this->generateSalt();
        $token = $this->pepper . $salt . $userId . microtime(true); // Concatenate pepper, salt, user ID, and timestamp
        $hashedToken = hash('sha256', $token); // Hash the concatenated string

        $expiresAt = new UTCDateTime(strtotime('+20 minutes') * 1000); // Expiry in 20 minutes

        $this->collection->insertOne([
            'token' => $hashedToken,
            'salt' => $salt,
            'user_id' => $userId,
            'expires_at' => $expiresAt
        ]);

        return $hashedToken;
    }

    public function validateToken(string $token, string $userId): bool
    {
        $result = $this->collection->findOne([
            'token' => $token,
            'user_id' => $userId,
            'expires_at' => ['$gt' => new UTCDateTime()]
        ]);

        if ($result) {
            // Introduce a delay of 5 milliseconds to defend against timing attacks
            usleep(5000); // 5000 microseconds = 5 milliseconds

            // Token is valid, update its expiration time
            $newExpiry = new UTCDateTime(strtotime('+20 minutes') * 1000);
            $this->collection->updateOne(
                ['token' => $token],
                ['$set' => ['expires_at' => $newExpiry]]
            );

            return true;
        }

        return false; // Token is invalid or expired
    }

    private function generateSalt(): string
    {
        return bin2hex(random_bytes(16)); // Generate a 32-character random salt
    }
}
