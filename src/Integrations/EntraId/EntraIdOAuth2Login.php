<?php

declare(strict_types=1);

namespace Packeton\Integrations\EntraId;

use Packeton\Attribute\AsIntegration;
use Packeton\Integrations\Base\BaseIntegrationTrait;
use Packeton\Integrations\LoginInterface;
use Packeton\Integrations\Model\OAuth2State;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface as UG;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[AsIntegration('entra_id')]
class EntraIdOAuth2Login implements LoginInterface
{
    use BaseIntegrationTrait;

    protected $name;
    protected $separator = ' ';
    protected $defaultScopes = ['openid', 'email', 'profile'];

    public function __construct(
        protected array $config,
        protected HttpClientInterface $httpClient,
        protected RouterInterface $router,
        protected OAuth2State $state,
    ) {
        $this->config["tenant_id"] = $this->config['tenant_id'] ?? 'common';
        $this->name = $config['name'];
        if (empty($this->config['default_roles'])) {
            $this->config['default_roles'] = ['ROLE_MAINTAINER', 'ROLE_SSO_ENTRA_ID'];
        }
    }

    public function redirectOAuth2Url(?Request $request = null, array $options = []): Response
    {
        return $this->getAuthorizationResponse(
            'https://login.microsoftonline.com/' . $this->config['tenant_id'] . '/oauth2/v2.0/authorize',
            $options
        );
    }

    public function getAccessToken(Request $request, array $options = []): array
    {
        if (!$request->get('code') || !$this->checkState($request->get('state'))) {
            throw new BadRequestHttpException('No "code" and "state" parameter was found!');
        }

        $route = $this->state->getStateBag()->get('route');
        $redirectUrl = $this->router->generate($route, ['alias' => $this->name], UG::ABSOLUTE_URL);
        $query = [
            'client_id' => $this->config['client_id'],
            'client_secret' => $this->config['client_secret'],
            'code'  => $request->get('code'),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redirectUrl,
        ];

        $response = $this->httpClient->request('POST',
            'https://login.microsoftonline.com/' . $this->config['tenant_id'] . '/oauth2/v2.0/token',
            ['body' => $query]
        );

        return $response->toArray();
    }

    public function fetchUser(array|Request $request, array $options = [], ?array &$accessToken = null): array
    {
        $accessToken ??= $request instanceof Request ? $this->getAccessToken($request) : $request;

        $response = $this->httpClient->request('GET',
            'https://graph.microsoft.com/oidc/userinfo',
            $this->getAuthorizationHeaders($accessToken)
        );

        $data = $response->toArray();

        if (empty($data['email'])) {
            throw new BadRequestHttpException('No email returned from Microsoft Graph oidc userinfo.');
        }

        $email = $data['email'];

        return [
            'user_name' => explode('@', $email)[0],
            'user_identifier' => $email,
            'external_id' => $this->name . ':' . ($data['id'] ?? $email),
            '_type' => self::LOGIN_EMAIL,
        ];
    }

    protected function getAuthorizationHeaders(array $token): array
    {
        return array_merge_recursive($this->config['http_options'] ?? [], [
            'headers' => [
                'Authorization' => "Bearer {$token['access_token']}",
                'Accept' => 'application/json',
            ]
        ]);
    }
}
