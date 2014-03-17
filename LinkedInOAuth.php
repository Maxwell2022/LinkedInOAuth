<?php

namespace Maxwell\LinkedIn;

use Maxwell\OAuthClient\AbstractOAuthClient;
use Maxwell\LinkedIn\Exception\LinkedInException;

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
    public function getAuthorizeURL($redirectURI=null, $scope=null, $state=null, $responseType='code')
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
     * Exchange request code for an access token
     *
     * @param string $code
     * @param null $redirectURI
     * @return mixed
     */
    public function getAccessToken($code, $redirectURI=null)
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
     * @param $uri
     * @param array $parameters
     * @param array $headers
     * @return mixed
     */
    public function get($uri, $parameters=array(), $headers=array())
    {
        $headers = array_merge(array(
            "Content-type: ".$this->getContentTypeFormat(),
            "x-li-format: ".self::DEFAULT_FORMAT
        ), $headers);
        return $this->request($uri, 'GET', $parameters, $headers);
    }

    /**
     * Use this function to make calls to the LinkedIn OAuth2 API.
     *
     * @see https://developer.linkedin.com/apis for availible calls.
     *
     * @param string $uri
     * @param string $method
     * @param array $parameters
     * @param array $headers
     * @param null $rawencoding
     * @return mixed
     */
    public function request($uri, $method='GET', $parameters=array(), $headers=array(), $rawencoding=null)
    {
        // Query parameters needed to make a basic OAuth transaction
        $params = array();

        // Set the oauth token if we have one
        if (null !== $this->getCurrentOAuthToken()) {
            $params['oauth2_access_token'] = $this->getCurrentOAuthToken();
        }

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
            $parameters = array_merge($params, $parameters);
            $url .= '?' . http_build_query($parameters);
            $response = $this->http($url, 'GET', array(), $headers);
        } else {

            $url .= '?' . http_build_query($params);
            if ('json' == $rawencoding) {
                $parameters = json_encode($parameters);
            }

            $response = $this->http($url, $method, $parameters, $headers);
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
     * @throws LinkedInException
     *
     * @see https://developer.linkedin.com/documents/share-api#usage
     */
    public function publish($data)
    {
        if (!is_array($data)) {
            throw new LinkedInException('Content information must be stored in an array. Cannot publish update');
        }

        return $this->post('people/~/shares', $data, array(
            "Except:",
            "Content-type: ".$this->getContentTypeFormat(),
            "x-li-format: ".self::DEFAULT_FORMAT
        ), 'json');
    }
}
