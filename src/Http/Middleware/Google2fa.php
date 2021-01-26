<?php

namespace Project383\Google2fa\Http\Middleware;

use Closure;
use Project383\Google2fa\Google2FAAuthenticator;
use PragmaRX\Google2FA\Google2FA as G2fa;
use PragmaRX\Recovery\Recovery;

/**
 * Class Google2fa
 * @package Project383\Google2fa\Http\Middleware
 */
class Google2fa
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure $next
     * @return mixed
     * @throws \PragmaRX\Google2FA\Exceptions\InsecureCallException
     */
    public function handle($request, Closure $next)
    {
        if (!config('383project2fa.enabled')) {
            return $next($request);
        }
        if ($request->path() === '2fa/confirm' || $request->path() === '2fa/authenticate'
            || $request->path() === '2fa/register') {
            return $next($request);
        }
        $authenticator = app(Google2FAAuthenticator::class)->boot($request);
        if (auth()->guest() || $authenticator->isAuthenticated()) {
            return $next($request);
        }
        if (empty(auth()->user()->user2fa) || auth()->user()->user2fa->google2fa_enable === 0) {

            $google2fa = new G2fa();
            $recovery = new Recovery();
            $secretKey = $google2fa->generateSecretKey();
            $data['recovery'] = $recovery
                ->setCount(config('383project2fa.recovery_codes.count'))
                ->setBlocks(config('383project2fa.recovery_codes.blocks'))
                ->setChars(config('383project2fa.recovery_codes.chars_in_block'))
                ->toArray();

            $user2faModel = config('383project2fa.models.user2fa');
            $user2faModelForeignKey = config('383project2fa.models.user_foreign_key');
            $user2faModel::where($user2faModelForeignKey, auth()->user()->id)->delete();

            $user2fa = new $user2faModel();
            $user2fa->{$user2faModelForeignKey} = auth()->user()->id;
            $user2fa->google2fa_secret = $secretKey;
            $user2fa->recovery = json_encode($data['recovery']);
            $user2fa->save();

            return response(view('google2fa::recovery', $data));
        }

        return response(view('google2fa::authenticate'));
    }
}