<?php

namespace Maxwell\LinkedIn;

use Maxwell\OAuthClient\OAuth;

/**
 * LinkedIn OAuth class
 */
class LinkedInOAuth
{
    const ACCESS_TOKEN_URL = 'https://www.linkedin.com/uas/oauth2/accessToken';
    const AUTHENTICATE_URL = 'https://www.linkedin.com/uas/oauth2/authorization';
    const AUTHORIZE_URL = 'https://www.linkedin.com/uas/oauth2/authorization';
    const REQUEST_TOKEN_URL = 'https://www.linkedin.com/uas/oauth2/authorization';

    const API_ENTRY_POINT = 'https://api.linkedin.com/v1/';

    /**
     * @var string Contains the last HTTP status code returned.
     */
    public $http_code;

    /**
     * @var string Contains the last API call.
     */
    public $url;

    /**
     * @var int Set timeout default.
     */
    public $timeout = 30;

    /**
     * @var int Set connect timeout.
     */
    public $connecttimeout = 30;

    /**
     * @var bool Verify SSL Certificate
     */
    public $ssl_verifypeer = false;

    /**
     * @var string Response format
     */
    public $format = 'json';

    /**
     * @var bool Decode returned json data
     */
    public $decode_json = true;

    /**
     * @var array Contains the last HTTP headers returned
     */
    public $http_info;

    /**
     * @var string Set the user agent
     */
    public $useragent = 'LinkedInOAuth v0.2.0-beta2';

    /**
     * @var string User token
     */
    protected $token;

    /**
     * @var string App client id
     */
    protected $clientId;

    /**
     * @var string App client id
     */
    protected $clientSecret;

    /**
     * @var string Redirect URL of the authentication
     */
    protected $redirectURI;

    protected $consumer;
    protected $sha1_method;

    /**
     * construct LinkedInOAuth object
     *
     * @param $consumer_key
     * @param $consumer_secret
     * @param null $oauth_token
     * @param null $oauth_token_secret
     */
    function __construct($consumer_key, $consumer_secret, $redirectURI, $oauth_token = null, $oauth_token_secret = null)
    {
        $this->clientId = $consumer_key;
        $this->clientSecret = $consumer_secret;
        $this->redirectURI = $redirectURI;

        $this->consumer = new OAuth\Consumer($consumer_key, $consumer_secret, $redirectURI);
        $this->sha1_method = new OAuth\SignatureMethodHMAC();
    }

    /**
     * Get the authorize URL
     *
     * @param null $redirectURL
     * @param string $scope
     * @param null $state
     * @param string $responseType
     *
     * @return string
     */
    function getAuthorizeURL($redirectURI = null, $scope = 'basic', $state = null, $responseType = 'code')
    {
        $params = array(
            'client_id' => $this->clientId,
            'scope' => $scope,
            'response_type' => $responseType,
            'redirect_uri' => $this->getRedirectUri($redirectURI)
        );

        if (null !== $state) {
            $params['state'] = $state;
        }

        return self::AUTHORIZE_URL . '?' . http_build_query($params);
    }

    /**
     * Exchange request token and secret for an access token and
     * secret, to sign API calls.
     *
     * @param bool $oauth_verifier
     * @return array ("oauth_token" => "the-access-token",
     *                "oauth_token_secret" => "the-access-secret",
     *                "user_id" => "9436992",
     *                "screen_name" => "abraham")
     */
    function getAccessToken($code, $redirectURI = null)
    {
        $parameters = array(
            'code' => $code,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->getRedirectUri($redirectURI)
        );

        return $this->oAuthRequest(self::ACCESS_TOKEN_URL, 'POST', $parameters);
    }

    /**
     * One time exchange of username and password for access token and secret.
     *
     * @param $username
     * @param $password
     * @return array ("oauth_token" => "the-access-token",
     *                "oauth_token_secret" => "the-access-secret",
     *                "user_id" => "9436992",
     *                "screen_name" => "abraham",
     *                "x_auth_expires" => "0")
     */
    function getXAuthToken($username, $password)
    {
        $parameters = array();
        $parameters['x_auth_username'] = $username;
        $parameters['x_auth_password'] = $password;
        $parameters['x_auth_mode'] = 'client_auth';
        $request = $this->oAuthRequest(self::ACCESS_TOKEN_URL, 'POST', $parameters);
        $token = OAuth\Util::parse_parameters($request);
        $this->token = new OAuth\Consumer($token['oauth_token'], $token['oauth_token_secret']);

        return $token;
    }

    /**
     * GET wrapper for oAuthRequest.
     *
     * @param $url
     * @param array $parameters
     * @return API|mixed
     */
    function get($url, $parameters = array())
    {
        $response = $this->oAuthRequest($url, 'GET', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }

        return $response;
    }

    /**
     * POST wrapper for oAuthRequest.
     *
     * @param $url
     * @param array $parameters
     * @return API|mixed
     */
    function post($url, $parameters = array())
    {
        $response = $this->oAuthRequest($url, 'POST', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }

        return $response;
    }

    /**
     * DELETE wrapper for oAuthRequest.
     *
     * @param $url
     * @param array $parameters
     * @return API|mixed
     */
    function delete($url, $parameters = array())
    {
        $response = $this->oAuthRequest($url, 'DELETE', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }

        return $response;
    }

    /**
     * Format and sign an OAuth / API request
     *
     * @param $url
     * @param $method
     * @param $parameters
     * @return API
     */
    function oAuthRequest($url, $method, $parameters)
    {
        if (strrpos($url, 'https://') !== 0 && strrpos($url, 'http://') !== 0) {
            $url = self::API_ENTRY_POINT.$url;
        }

        $request = OAuth\Request::from_consumer_and_token($this->consumer, $this->token, $method, $url, $parameters);
        $request->sign_request($this->sha1_method, $this->consumer, $this->token);
        switch ($method) {
            case 'GET':
                return $this->http($request->to_url(), 'GET');
            default:
                return $this->http($request->get_normalized_http_url(), $method, $request->to_postdata());
        }
    }

    /**
     * Make an HTTP request
     *
     * @param $url
     * @param $method
     * @param null $postfields
     * @return mixed
     */
    function http($url, $method, $postfields = null)
    {
        $this->http_info = array();
        $ci = curl_init();
        /* Curl settings */
        curl_setopt($ci, CURLOPT_USERAGENT, $this->useragent);
        curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, $this->connecttimeout);
        curl_setopt($ci, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ci, CURLOPT_HTTPHEADER, array('Expect:'));
        curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->ssl_verifypeer);
        curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'getHeader'));
        curl_setopt($ci, CURLOPT_HEADER, false);

        switch ($method) {
            case 'POST':
                curl_setopt($ci, CURLOPT_POST, true);
                if (!empty($postfields)) {
                    curl_setopt($ci, CURLOPT_POSTFIELDS, $postfields);
                }
                break;
            case 'DELETE':
                curl_setopt($ci, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if (!empty($postfields)) {
                    $url = "{$url}?{$postfields}";
                }
        }

        curl_setopt($ci, CURLOPT_URL, $url);
        $response = curl_exec($ci);
        $this->http_code = curl_getinfo($ci, CURLINFO_HTTP_CODE);
        $this->http_info = array_merge($this->http_info, curl_getinfo($ci));
        $this->url = $url;
        curl_close($ci);

        return $response;
    }

    /**
     * Get the header info to store.
     *
     * @param $ch
     * @param $header
     * @return int
     */
    function getHeader($ch, $header)
    {
        $i = strpos($header, ':');
        if (!empty($i)) {
            $key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
            $value = trim(substr($header, $i + 2));
            $this->http_header[$key] = $value;
        }

        return strlen($header);
    }

    /**
     * Added to go well with the Symfony2 DIC
     *
     * @param  $oauth_token
     * @param  $oauth_token_secret
     * @return void
     */
    function setOAuthToken($oauth_token, $oauth_token_secret)
    {
        $this->token = new OAuth\Consumer($oauth_token, $oauth_token_secret);
    }

    /**
     * Avoid the notices if the token is not set
     *
     * @param  $request
     * @return array
     */
    function getToken($request)
    {
        $token = OAuth\Util::parse_parameters($request);
        if (isset($token['oauth_token'], $token['oauth_token_secret'])) {
            $this->token = new OAuth\Consumer($token['oauth_token'], $token['oauth_token_secret']);
        }

        return $token;
    }

    /**
     * @param null $uri
     * @return string
     */
    protected function getRedirectUri($uri = null)
    {
        $redirectURI = $this->redirectURI;

        if (null !== $uri) {
            $redirectURI = $uri;
        }

        if (!preg_match('#^http#i', $redirectURI)) {
            $protocol = 'http://';
            if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
                $protocol = 'https://';
            }
            $redirectURI = $protocol . $_SERVER['HTTP_HOST'] . $redirectURI;
        }

        return $redirectURI;
    }
}