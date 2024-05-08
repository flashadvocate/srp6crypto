<?php

namespace SRP6Crypto;

final class Verifier
{
    private string $username;
    private string $password;
    private ?string $salt;
    private ?string $verifier;

    public function __construct(string $username, string $password, ?string $salt = null, ?string $verifier = null)
    {
        $this->username = $username;
        $this->password = $password;
        $this->salt = $salt;
        $this->verifier = $verifier;
    }

    /**
     * Generates a new salt and verifier.
     *
     * @throws \Exception
     * @return array Contains salt and verifier.
     */
    public function generate(): array
    {
        $this->salt = random_bytes(32);
        $verifier = $this->calculate();

        return [$this->salt, $verifier];
    }

    /**
     * Verifies if the provided verifier matches the calculated one.
     *
     * @return bool True if the verifiers match, false otherwise.
     */
    public function verify(): bool
    {
        $checkVerifier = $this->calculate();

        return $this->verifier === $checkVerifier;
    }

    /**
     * Calculates the verifier based on the username, password, and salt.
     *
     * @return string The calculated verifier.
     */
    private function calculate(): string
    {
        // Constants for the algorithm
        $g = gmp_init(7);
        $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

        // Hash the username and password combination
        $hash = sha1(strtoupper($this->username . ':' . $this->password), true);
        $saltedHash = sha1($this->salt . $hash, true);

        // Convert the salted hash to an integer (little-endian)
        $hashInt = gmp_import($saltedHash, 1, GMP_LSW_FIRST);

        // Compute g^hashInt mod N
        $verifier = gmp_powm($g, $hashInt, $N);

        // Convert the verifier back to a byte array (little-endian)
        $byteArrayVerifier = gmp_export($verifier, 1, GMP_LSW_FIRST);

        // Pad the result to 32 bytes (little-endian)
        return str_pad($byteArrayVerifier, 32, "\0", STR_PAD_RIGHT);
    }
}
