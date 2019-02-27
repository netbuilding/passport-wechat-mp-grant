<?php
/**
 * Created by PhpStorm.
 * User: isaacliu
 * Date: 2019-02-27
 * Time: 15:52
 */

namespace NetBuilding\PassportWechatMpGrant;

use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;

class WechatMpGrantServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        app(AuthorizationServer::class)->enableGrantType($this->makeWechatMpGrant(), Passport::tokensExpireIn());
    }

    protected function makeWechatMpGrant()
    {
        $grant = new WechatMpGrant(
            $this->app->make(RefreshTokenRepository::class)
        );
        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        return $grant;
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}
