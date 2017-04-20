<?php

namespace narekps\PhalconAuth;

/**
 * Interface IdentityInterface
 *
 * @package narekps\PhalconAuth
 */
interface IdentityInterface
{
    /**
     * @param string $email
     *
     * @return IdentityInterface|null
     */
    public static function findByEmail(string $email): ?IdentityInterface;

    /**
     * @param string $identifier
     *
     * @return IdentityInterface|null
     */
    public static function findByIdentifier(string $identifier): ?IdentityInterface;

    /**
     * @return string
     */
    public function getIdentifier(): string;

    /**
     * @return string
     */
    public function getPassword(): string;

    /**
     * @return string
     */
    public function getEmail(): string;
}
