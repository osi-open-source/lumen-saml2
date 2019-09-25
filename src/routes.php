<?php

use Illuminate\Support\Facades\Route;

Route::group(['middleware' => config('saml2_settings.routesMiddleware'), 'prefix' => config('saml2_settings.routesPrefix').'/'], function() {
    Route::group(['prefix' => '{idpName}'], function () {
        $saml2_controller = config('saml2_settings.saml2_controller', 'Ibpavlov\Saml2\Http\Controllers\Saml2Controller');
        Route::get('/logout', array(
            'as' => 'saml2_logout',
            'uses' => $saml2_controller.'@logout',
        ));

        Route::get('/login', array(
            'as' => 'saml2_login',
            'uses' => $saml2_controller.'@login',
        ));

        Route::get('/metadata', array(
            'as' => 'saml2_metadata',
            'uses' => $saml2_controller.'@metadata',
        ));

        Route::post('/acs', array(
            'as' => 'saml2_acs',
            'uses' => $saml2_controller.'@acs',
        ));

        Route::get('/sls', array(
            'as' => 'saml2_sls',
            'uses' => $saml2_controller.'@sls',
        ));
    });
});
