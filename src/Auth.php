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
            throw new InvalidConfigException(__CLASS__ . '::identityClass must be set.');
        }
        $this->identityClass = $this->config->get('identityClass');
        if (!is_subclass_of($this->identityClass, IdentityInterface::class)) {
            throw new InvalidConfigException(__CLASS__ . '::identityClass must be implement IdentityInterface.');
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
            $key = $this->config->get('session_key');
            if ($this->session->has($key)) {
                $session = $this->session->get($key);
                $class = $this->identityClass;
                $identity = $class::findById($session['user_id']);
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
        if ($this->session->has($this->config->get('session_key'))) {
            $this->session->remove($this->config->get('session_key'));
        }
        if ($this->cookies->has('RMU')) {
            $this->cookies->get('RMU')->delete();
        }
        if ($this->cookies->has('RMT')) {
            $this->cookies->get('RMT')->delete();
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
        $session = [
            'user_id' => $identity->getIdentifier(),
        ];
        $this->session->set($this->config->get('session_key'), $session);

        if ($remember === true) {
            $this->createRememberEnvironment($identity);
        }

        return true;
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
    public function createRememberEnvironment(IdentityInterface $identity): void
    {
        $userAgent = $this->request->getUserAgent();
        $token = md5($identity->getEmail() . $identity->getPassword() . $userAgent);
        $expire = time() + 86400 * 8;
        $this->cookies->set('RMU', $identity->getIdentifier(), $expire);
        $this->cookies->set('RMT', $token, $expire);

        return;
    }

    /**
     * @return bool
     */
    public function hasRememberMe(): bool
    {
        return $this->cookies->has('RMU') && $this->cookies->has('RMT');
    }

    /**
     * @return bool
     */
    public function loginWithRememberMe(): bool
    {
        if (!$this->hasRememberMe()) {
            return false;
        }

        $userId = $this->cookies->get('RMU')->getValue();
        $cookieToken = $this->cookies->get('RMT')->getValue();

        $class = $this->identityClass;
        /** @var IdentityInterface $identity */
        $identity = $class::findById($userId);
        if ($identity) {
            $userAgent = $this->request->getUserAgent();
            $token = md5($identity->getEmail() . $identity->getPassword() . $userAgent);

            if ($cookieToken == $token) {
                // Check if the cookie has not expired, TODO: save to database
                //if ((time() - (86400 * 8)) < $remember->createdAt) {

                $session = [
                    'user_id' => $identity->getIdentifier(),
                ];
                $this->session->set($this->config->get('session_key'), $session);

                return true;
                //}
            }
        }

        $this->logout();

        return false;
    }
}
