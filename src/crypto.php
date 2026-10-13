<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verify_password(string $password, string $stored): bool {
    return password_verify($password, $stored);
}

function issue_reset_token(string $email): string {
    // Generate a cryptographically secure, unpredictable token.
    $token = bin2hex(random_bytes(32));

    // Store only a hash of the token in the database.
    $tokenHash = hash("sha256", $token);

    $pdo = db();

    $pdo->prepare(
        "DELETE FROM reset_tokens WHERE email = ?"
    )->execute([$email]);

    $pdo->prepare(
        "INSERT INTO reset_tokens (email, token, created_at)
         VALUES (?, ?, datetime('now'))"
    )->execute([$email, $tokenHash]);

    // Return the original token to the reset flow.
    return $token;
}

function consume_reset_token(string $email, string $token): bool {
    $pdo = db();

    // Lock the SQLite database for this transaction so two
    // simultaneous requests cannot successfully consume one token.
    $pdo->exec("BEGIN IMMEDIATE");

    try {
        $stmt = $pdo->prepare(
            "SELECT token, created_at
             FROM reset_tokens
             WHERE email = ?"
        );
        $stmt->execute([$email]);
        $row = $stmt->fetch();

        if (!$row) {
            $pdo->exec("ROLLBACK");
            return false;
        }

        // Reject expired tokens (15-minute lifetime).
        $createdAt = strtotime($row["created_at"]);

        if (
            $createdAt === false ||
            $createdAt > time() ||
            time() - $createdAt > 900
        ) {
            $pdo->prepare(
                "DELETE FROM reset_tokens WHERE email = ?"
            )->execute([$email]);

            $pdo->exec("COMMIT");
            return false;
        }

        // Compare the hash of the submitted token with the stored hash.
        $submittedHash = hash("sha256", $token);

        if (!hash_equals((string) $row["token"], $submittedHash)) {
            $pdo->exec("ROLLBACK");
            return false;
        }

        // Delete the token after successful validation.
        $delete = $pdo->prepare(
            "DELETE FROM reset_tokens
             WHERE email = ? AND token = ?"
        );
        $delete->execute([$email, $submittedHash]);

        if ($delete->rowCount() !== 1) {
            $pdo->exec("ROLLBACK");
            return false;
        }

        $pdo->exec("COMMIT");
        return true;

    } catch (Throwable $e) {
        $pdo->exec("ROLLBACK");
        throw $e;
    }
}