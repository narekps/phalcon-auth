<?php

namespace narekps\PhalconAuth;

use Phalcon\Mvc\User\Component;
use Phalcon\Config;

/**
 * Class Auth
 *
 * @package narekps\PhalconAuth
 */
class Auth extends Component
{
    /**
     * The default password cost.
     */
    private const PASSWORD_COST = 14;

    /**
     * Default cookie time to life.
     */
    private const COOKIE_TTL = 3600 * 24 * 30;

    /**
     * @var array
     */
    private $config;

    /**
     * @var IdentityInterface|null
     */
    private $identity;

    /**
     * @var string
     */
    private $identityClass;

    /**
     * Auth constructor.
     *
     * @param Config $config
     *
     * @throws InvalidConfigException
     */
    public function __construct(Config $config)
    {
        $this->config = $config;
        if (!$this->config->offsetExists('identityClass')) {
            throw new InvalidConfigException('The parameter "identityClass" must be set in config');
        }
        $this->identityClass = $this->config->get('identityClass');
        if (!is_subclass_of($this->identityClass, IdentityInterface::class)) {
            throw new InvalidConfigException('The identityClass must be implement ' . IdentityInterface::class);
        }
        if (!$this->config->offsetExists('cryptSalt')) {
            throw new InvalidConfigException('The parameter "cryptSalt" must be set in config');
        }
        if (!$this->config->offsetExists('sessionKey')) {
            throw new InvalidConfigException('The parameter "sessionKey" must be set in config');
        }
        if (!$this->config->offsetExists('cookie')) {
            throw new InvalidConfigException('The parameter "cookie" must be set in config');
        }
        $cookieCfg = $this->config->get('cookie');
        if (!$cookieCfg->offsetExists('name')) {
            throw new InvalidConfigException('The parameter "cookie.name" must be set in config');
        }
        if (!$cookieCfg->offsetExists('domain')) {
            throw new InvalidConfigException('The parameter "cookie.domain" must be set in config');
        }
    }

    /**
     * @param string $plainPassword
     *
     * @return string
     * @throws Exception
     */
    public function hash(string $plainPassword): string
    {
        $options = [
            'cost' => $this->config->get('passwordCost', self::PASSWORD_COST),
        ];
        $hash = password_hash($plainPassword, PASSWORD_BCRYPT, $options);
        if ($hash === false) {
            throw new Exception('Could not generate hash');
        }

        return $hash;
    }

    /**
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * @return IdentityInterface|null
     */
    public function getIdentity(): ?IdentityInterface
    {
        if (!$this->identity instanceof IdentityInterface) {
            if ($sessionData = $this->getSessionData()) {
                $class = $this->identityClass;
                $identity = $class::findById($sessionData['user_id']);
                if ($identity instanceof IdentityInterface) {
                    $this->identity = $identity;
                }
            }
        }

        return $this->identity;
    }

    /**
     * Logout the current user
     */
    public function logout(): void
    {
        if ($this->session->has($this->config->get('sessionKey'))) {
            $this->session->remove($this->config->get('sessionKey'));
        }
        if ($this->cookies->has($this->config->get('cookie')->get('name'))) {
            $this->cookies->get($this->config->get('cookie')->get('name'))->delete();
        }
        $this->identity = null;

        return;
    }

    /**
     * @param string $email
     * @param string $password
     * @param bool   $remember
     *
     * @return bool
     * @throws Exception
     */
    public function login(string $email, string $password, bool $remember = false): bool
    {
        $class = $this->identityClass;
        $identity = $class::findByEmail($email);

        if (!$identity instanceof IdentityInterface) {
            throw new Exception('Wrong email/password combination');
        }

        if (!$this->verify($password, $identity->getPassword())) {
            throw new Exception('Wrong email/password combination');
        }

        $this->identity = $identity;
        $this->saveSessionData($identity);

        if ($remember === true) {
            $this->saveCookieData($identity);
        }

        return true;
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private function encryptData(string $data): string
    {
        $cryptSalt = $this->config->get('cryptSalt');
        $data = $this->crypt->encrypt($data, $cryptSalt);

        return $data;
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private function decryptData(string $data): string
    {
        $cryptSalt = $this->config->get('cryptSalt');
        $data = $this->crypt->decrypt($data, $cryptSalt);

        return $data;
    }

    /**
     * @param IdentityInterface $identity
     */
    private function saveSessionData(IdentityInterface $identity): void
    {
        $key = $this->config->get('sessionKey');
        $data = [
            'user_id' => $identity->getIdentifier(),
        ];
        $this->session->set($key, $this->encryptData(json_encode($data)));
    }

    /**
     * @return array|null
     */
    private function getSessionData(): ?array
    {
        $data = null;
        $key = $this->config->get('sessionKey');
        if ($this->session->has($key)) {
            $data = json_decode($this->decryptData($this->session->get($key)), true);
            if (!is_array($data)) {
                $data = null;
            }
        }

        return $data;
    }

    /**
     * @return bool
     */
    public function loggedIn(): bool
    {
        if ($this->hasRememberMe()) {
            $this->loginWithRememberMe();
        }

        return $this->getIdentity() instanceof IdentityInterface;
    }

    /**
     * @param IdentityInterface $identity
     */
    public function saveCookieData(IdentityInterface $identity): void
    {
        /** @var \Phalcon\Config $cookieCfg */
        $cookieCfg = $this->config->get('cookie');
        $key = $cookieCfg->get('name');
        $domain = $cookieCfg->get('domain');
        $expire = static::COOKIE_TTL;
        if ($cookieCfg->offsetExists('expire')) {
            $expire = $cookieCfg->get('expire');
        }
        $path = "/";
        if ($cookieCfg->offsetExists('path')) {
            $path = $cookieCfg->get('path');
        }
        $secure = false;
        if ($cookieCfg->offsetExists('secure')) {
            $secure = $cookieCfg->get('secure');
        }
        $httpOnly = false;
        if ($cookieCfg->offsetExists('httpOnly')) {
            $httpOnly = $cookieCfg->get('httpOnly');
        }

        $token = $this->generateCookieToken($identity);
        $data = [
            'user_id' => $identity->getIdentifier(),
            'token'   => $token,
        ];
        $data = $this->encryptData(json_encode($data));
        $expire += time();
        $this->cookies->set($key, $data, $expire, $path, $secure, $domain, $httpOnly);

        return;
    }

    /**
     * @return array|null
     */
    private function getCookieData(): ?array
    {
        $data = null;
        /** @var \Phalcon\Config $cookieCfg */
        $cookieCfg = $this->config->get('cookie');
        $key = $cookieCfg->get('name');
        if ($this->cookies->has($key)) {
            $data = json_decode($this->decryptData($this->cookies->get($key)), true);
            if (!is_array($data)) {
                $data = null;
            }
        }

        return $data;
    }

    /**
     * @param IdentityInterface $identity
     *
     * @return string
     */
    private function generateCookieToken(IdentityInterface $identity)
    {
        $userAgent = $this->request->getUserAgent();
        $token = md5($identity->getEmail() . $identity->getPassword() . $userAgent);

        return $token;
    }

    /**
     * @return bool
     */
    public function hasRememberMe(): bool
    {
        return $this->cookies->has($this->config->get('cookie')->get('name'));
    }

    /**
     * @return bool
     */
    public function loginWithRememberMe(): bool
    {
        if (!$this->hasRememberMe()) {
            return false;
        }

        $cookieData = $this->getCookieData();
        if (!is_array($cookieData)) {
            return false;
        }

        $userId = $cookieData['user_id'];
        $cookieToken = $cookieData['token'];

        $class = $this->identityClass;
        /** @var IdentityInterface $identity */
        $identity = $class::findById($userId);
        if ($identity) {
            $token = $this->generateCookieToken($identity);

            if ($cookieToken == $token) {
                // Check if the cookie has not expired, TODO: save to database
                //if ((time() - (86400 * 8)) < $remember->createdAt) {

                $this->saveSessionData($identity);
                $this->identity = $identity;

                return true;
                //}
            }
        }

        $this->logout();

        return false;
    }
}
