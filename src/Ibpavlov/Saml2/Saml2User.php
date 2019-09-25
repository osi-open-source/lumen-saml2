<?php

namespace Ibpavlov\Saml2;

use Laravel\Lumen\Routing\UrlGenerator;
use OneLogin\Saml2\Auth as OneLogin_Saml2_Auth;

/**
 * A simple class that represents the user that 'came' inside the saml2 assertion
 * Class Saml2User
 * @package Ibpavlov\Saml2
 */
class Saml2User
{

    protected $auth;

    /**
     * Saml2User constructor.
     * @param OneLogin_Saml2_Auth $auth
     */
    function __construct(OneLogin_Saml2_Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * @return string User Id retrieved from assertion processed this request
     */
    function getUserId()
    {
        $auth = $this->auth;

        return $auth->getNameId();

    }

    /**
     * @return array attributes retrieved from assertion processed this request
     */
    function getAttributes()
    {
        $auth = $this->auth;

        return $auth->getAttributes();
    }

    /**
     * Returns the requested SAML attribute
     *
     * @param string $name The requested attribute of the user.
     * @return array|null Requested SAML attribute ($name).
     */
    function getAttribute($name)
    {
        $auth = $this->auth;

        return $auth->getAttribute($name);
    }

    /**
     * @return array attributes retrieved from assertion processed this request
     */
    function getAttributesWithFriendlyName()
    {
        $auth = $this->auth;

        return $auth->getAttributesWithFriendlyName();
    }

    /**
     * @return string the saml assertion processed this request
     */
    function getRawSamlAssertion()
    {
        return app('request')->input('SAMLResponse'); //just this request
    }

    /**
     * @return null|string
     */
    function getIntendedUrl()
    {
        $relayState = app('request')->input('RelayState'); //just this request

        $url = app(UrlGenerator::class);

        if ($relayState && $url->full() != $relayState) {
            return $relayState;
        }
        return null;
    }

    /**
     * Parses a SAML property and adds this property to this user or returns the value
     *
     * @param string $samlAttribute
     * @param string $propertyName
     * @return array|null
     */
    function parseUserAttribute($samlAttribute = null, $propertyName = null)
    {
        if (empty($samlAttribute)) {
            return null;
        }
        if (empty($propertyName)) {
            return $this->getAttribute($samlAttribute);
        }

        return $this->{$propertyName} = $this->getAttribute($samlAttribute);
    }

    /**
     * Parse the saml attributes and adds it to this user
     *
     * @param array $attributes Array of properties which need to be parsed, like this ['email' =>
     *     'urn:oid:0.9.2342.19200300.100.1.3']
     */
    function parseAttributes($attributes = [])
    {
        foreach ($attributes as $propertyName => $samlAttribute) {
            $this->parseUserAttribute($samlAttribute, $propertyName);
        }
    }

    /**
     * @return string|null
     */
    function getSessionIndex()
    {
        return $this->auth->getSessionIndex();
    }

    /**
     * @return string
     */
    function getNameId()
    {
        return $this->auth->getNameId();
    }

}
