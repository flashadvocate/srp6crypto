<?php

namespace SRP6Crypto;

final class Verifier
{
    public function __construct(
        private $username,
        private $password,
        private $salt = null,
        private $verifier = null,
    ) {}

    /**
     * @throws \Exception
     */
    public function generate(): array
    {
        $this->salt = random_bytes(32);

        $verifier = $this->calculate();

        return [
            $this->salt,
            $verifier
        ];
    }

    public function verify(): bool
    {
        $checkVerifier = $this->calculate($this->username, $this->password, $this->salt);

        return ($this->verifier === $checkVerifier);
    }

    private function calculate(): string
    {
        // algorithm constants
        $g = gmp_init(7);
        $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

        // hashed value, salted
        $hash = sha1(strtoupper($this->username . ':' . $this->password), TRUE);
        $salted = sha1($this->salt . $hash, TRUE);

        // convert to integer (little-endian)
        $salted = gmp_import($salted, 1, GMP_LSW_FIRST);

        // g^h2 mod N
        $verifier = gmp_powm($g, $salted, $N);

        // convert back to a byte array (little-endian)
        $verifier = gmp_export($verifier, 1, GMP_LSW_FIRST);

        // pad to 32 bytes, remember that zeros go on the end in little-endian!
        return str_pad($verifier, 32, chr(0), STR_PAD_RIGHT);
    }
}
