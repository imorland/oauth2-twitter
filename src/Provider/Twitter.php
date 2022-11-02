<?php

namespace IanM\OAuth2\Client\Provider;

use IanM\OAuth2\Client\Provider\Exception\TwitterIdentityProviderException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RandomLib\Factory as RandomLibFactory;

class Twitter extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * In addition to state, store a PKCE verifier that will be used when
     * getting the authorization token.
     *
     * @link https://www.oauth.com/oauth2-servers/pkce/authorization-code-exchange/
     *
     * @var string
     */
    protected string $pkceVerifier;

    /**
     * Get the unhashed PKCE Verifier string for the request.
     *
     * @return string
     */
    public function getPkceVerifier(): string
    {
        if (!isset($this->pkceVerifier)) {
            $this->pkceVerifier = $this->generatePkceVerifier();
        }

        return $this->pkceVerifier;
    }

    /**
     * {@inheritDoc}
     */
    public function getBaseAuthorizationUrl(): string
    {
        return 'https://twitter.com/i/oauth2/authorize';
    }

    /**
     * {@inheritDoc}
     */
    protected function getAuthorizationParameters(array $options): array
    {
        if (!isset($options['code_challenge'])) {
            $options['code_challenge'] = $this->generatePkceChallenge();
            $options['code_challenge_method'] = 'S256';
        }

        return parent::getAuthorizationParameters($options);
    }

    /**
     * {@inheritDoc}
     */
    protected function getAccessTokenRequest(array $params): RequestInterface
    {
        $request = parent::getAccessTokenRequest($params);

        $token_string = base64_encode($this->clientId . ':' . $this->clientSecret);

        return $request->withHeader('Authorization', "Basic $token_string");
    }

    /**
     * {@inheritDoc}
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return 'https://api.twitter.com/2/oauth2/token';
    }

    /**
     * {@inheritDoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return 'https://api.twitter.com/2/users/me';
    }

    /**
     * {@inheritDoc}
     */
    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $url = $this->getResourceOwnerDetailsUrl($token) . '?' . http_build_query(['user.fields' => 'id,name,profile_image_url,username']);

        $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new \UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }

    /**
     * {@inheritDoc}
     */
    protected function getDefaultScopes(): array
    {
        return [
            'tweet.read',
            'users.read',
            'offline.access',
        ];
    }

    /**
     * {@inheritDoc}
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * {@inheritDoc}
     *
     * @throws TwitterIdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() == 200) {
            return;
        }

        $error = $data['error_description'] ?? '';
        $code = $data['code'] ?? $response->getStatusCode();

        throw new TwitterIdentityProviderException($error, $code, $data);
    }

    /**
     * {@inheritDoc}
     */
    protected function createResourceOwner(array $response, AccessToken $token): TwitterResourceOwner
    {
        return new TwitterResourceOwner($response);
    }

    /**
     * {@inheritDoc}
     */
    private function base64Urlencode(string $param): string
    {
        return rtrim(strtr(base64_encode($param), '+/', '-_'), '=');
    }

    /**
     * Create a PKCE verifier string.
     *
     * @link https://www.oauth.com/oauth2-servers/pkce/authorization-request/
     *
     * @return string
     */
    public function generatePkceVerifier(): string
    {
        $generator = (new RandomLibFactory)->getMediumStrengthGenerator();
        return $generator->generateString(
            $generator->generateInt(43, 128), // Length between 43-128 characters
            '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~'
        );
    }

    /**
     * Get the hashed and encoded PKCE challenge string for the request.
     *
     * @param string $passed_verifier Verifier string to use. Defaults to $this->getPkceVerifier().
     * @return string
     */
    public function generatePkceChallenge(string $passed_verifier = null): string
    {
        $verifier = $passed_verifier ?? $this->getPkceVerifier();
        return $this->base64Urlencode(hash('SHA256', $verifier, true));
    }
}
