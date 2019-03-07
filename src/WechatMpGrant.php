<?php
/**
 * Created by PhpStorm.
 * User: isaacliu
 * Date: 2019-02-27
 * Time: 15:38
 */

namespace NetBuilding\PassportWechatMpGrant;

use DateInterval;
use Laravel\Passport\Bridge\User;
use http\Exception\RuntimeException;
use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Grant\AbstractGrant;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;

class WechatMpGrant extends AbstractGrant
{

    public function __construct(RefreshTokenRepository $refreshTokenRepository)
    {
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new DateInterval('P1M');
    }

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, DateInterval $accessTokenTTL)
    {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
        $user = $this->validateUser($request, $client);
        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());
        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $refreshToken = $this->issueRefreshToken($accessToken);
        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);
        return $responseType;
    }

    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client)
    {
        $code = $this->getRequestParameter('code', $request);
        if (is_null($code)) {
            throw OAuthServerException::invalidRequest('code');
        }
        $user = $this->getUserEntityByWechatCode($code, $client);
        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidCredentials();
        }
        return $user;
    }

    /**
     * @param $code
     * @return User
     * @throws \Exception
     */
    protected function getUserEntityByWechatCode($code)
    {
        $provider = config('auth.guards.api.provider');
        if (is_null($model = config('auth.providers.' . $provider . '.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }

        $token = app('wechat.mini_program')->auth->session($code);

        if (method_exists($model, 'findByOAuth')) {
            $user = (new $model)::findByOAuth('wechat_mp', $token['openid'], $token);
        } else {
            $user = (new $model)->where('openid', $token['openid'])->first();
        }
        if (!$user) {
            return;
        }

        return new User($user->getAuthIdentifier());
    }

    public function getIdentifier()
    {
        return 'wechat_mp';
    }

}
