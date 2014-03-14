<?php

namespace Maxwell\LinkedIn;

use Maxwell\OAuthClient\OAuth;
use Maxwell\OAuthClient\AbstractOAuthClient;
/**
 * LinkedIn OAuth class
 */
class LinkedInOAuth extends AbstractOAuthClient
{
    const ACCESS_TOKEN_URL = 'https://www.linkedin.com/uas/oauth2/accessToken';
    const AUTHENTICATE_URL = 'https://www.linkedin.com/uas/oauth2/authorization';
    const AUTHORIZE_URL = 'https://www.linkedin.com/uas/oauth2/authorization';
    const REQUEST_TOKEN_URL = 'https://www.linkedin.com/uas/oauth2/authorization';
    const API_ENTRY_POINT = 'https://api.linkedin.com/v1/';

    /**
     * Get the authorize URL
     *
     * @param null $redirectURL
     * @param array $scope list of scope space separated
     * @param null $state
     * @param string $responseType
     *
     * @return string
     */
    public function getAuthorizeURL($redirectURI = null, $scope = null, $state = null, $responseType = 'code')
    {
        $params = array(
            'client_id' => $this->getConsumerKey(),
            'response_type' => $responseType,
            'redirect_uri' => $this->getRedirectUri($redirectURI),
            'state' => md5(uniqid('', true))
        );

        if (is_array($scope) && !empty($scope)) {
            $params['scope'] = implode(' ', $scope);
        }

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
    public function getAccessToken($code, $redirectURI = null)
    {
        $params = array(
            'code' => $code,
            'client_id' => $this->getConsumerKey(),
            'client_secret' => $this->getConsumerSecret(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->getRedirectUri($redirectURI)
        );

        return $this->post(self::ACCESS_TOKEN_URL, $params);
    }

    /**
     * Use this function to make calls to the LinkedIn OAuth2 API.
     * See https://developer.linkedin.com/apis for availible calls.
     * @param type $method POST|GET|PUT|DELETE
     * @param type $resource Resource to make a call to. (eg. v1/people/~/connections)
     * @param type $body POST body data (Will be send as is if string is supplied, json_encoded if object or assoc array.)
     * @return type response object. Throws Exception on error.
     */
    public function request($uri, $method='GET', $parameters=array())
    {
        // Query parameters needed to make a basic OAuth transaction
        $params = array(
            'format' => self::DEFAULT_FORMAT,
        );

        // Set the oauth token if we have one
        if (null !== $this->getCurrentOAuthToken()) {
            $params['oauth2_access_token'] = $this->getCurrentOAuthToken();
        }

        $parameters = array_merge($params, $parameters);
        $url = $uri;

        if (!preg_match('#^http#i', $uri)) {

            // Remove starting slash if any
            if (preg_match('#^/#i', $uri)) {
                $uri = substr($uri, 1);
            }

            // Build the URL
            $url = self::API_ENTRY_POINT.$uri;
        }

        // build the http query
        if ('GET' === strtoupper(trim($method))) {
            $url .= '?' . http_build_query($parameters);
            $response = $this->http($url, 'GET');
        } else {
            $response = $this->http($url, $method, $parameters);
        }

        if ('json' == self::DEFAULT_FORMAT) {
            $json = json_decode($response, true);
            return null === $json ? $response : $json;
        }

        return $response;
    }

    /**
     * Publish a content on the Social network
     *
     * @param $data
     * @return bool|void
     * @throws \Exception
     */
    public function publish($data)
    {
        return false;
    }
}