[![Total Downloads](https://poser.pugx.org/maxwell2022/tumblroauth/downloads.png)](https://packagist.org/packages/maxwell2022/tumblroauth)

This API is based on https://github.com/kertz/twitteroauth
I've forked to add composer support
Initial modification has been done by Lucas

TumblrOAuth
------------

PHP library for working with Tumblr's OAuth API.

Flow Overview
=============

1. Build TumblrOAuth object using client credentials.
2. Request temporary credentials from Tumblr.
3. Build authorize URL for Tumblr.
4. Redirect user to authorize URL.
5. User authorizes access and returns from Tumblr.
6. Rebuild TumblrOAuth object with client credentials and temporary credentials.
7. Get token credentials from Tumblr.
8. Rebuild TumblrOAuth object with client credentials and token credentials.
9. Query Tumblr API.

Terminology
===========

The terminology has changed since 0.1.x to better match the draft-hammer-oauth IETF
RFC. You can read that at http://tools.ietf.org/html/draft-hammer-oauth. Some of the
terms will differ from those Tumblr uses as well.

client credentials - Consumer key/secret you get when registering an app with Tumblr.
temporary credentials - Previously known as the request token.
token credentials - Previously known as the access token.


Extended flow using example code
================================

To use TumblrOAuth with the Tumblr API you need *TumblrOAuth.php*, *OAuth.php* and
client credentials. You can get client credentials by registering your application at
[tumblr.com/oauth/apps](http://www.tumblr.com/oauth/apps).

Users start out on connect.php which displays the "Sign in with Tumblr" image hyperlinked
to redirect.php. This button should be displayed on your homepage in your login section. You can
save a static callback URL in the app settings page, in the config file or use a dynamic
callback URL later in step 2. In example use https://example.com/callback.php.

1) When a user lands on redirect.php we build a new TumblrOAuth object using the client credentials.
If you have your own configuration method feel free to use it instead of config.php.

    $connection = new TumblrOAuth(CONSUMER_KEY, CONSUMER_SECRET); // Use config.php client credentials
    $connection = new TumblrOAuth('abc890', '123xyz');

2) Using the built $connection object you will ask Tumblr for temporary credentials. The `oauth_callback` value is required.

    $temporary_credentials = $connection->getRequestToken(OAUTH_CALLBACK); // Use config.php callback URL.

3) Now that we have temporary credentials the user has to go to Tumblr and authorize the app
to access and updates their data. You can also pass a second parameter of FALSE to not use [Sign
in with Tumblr](https://dev.Tumblr.com/docs/auth/sign-Tumblr).

    $redirect_url = $connection->getAuthorizeURL($temporary_credentials); // Use Sign in with Tumblr
    $redirect_url = $connection->getAuthorizeURL($temporary_credentials, FALSE);

4) You will now have a Tumblr URL that you must send the user to.

    http://www.tumblr.com/oauth/authorize?oauth_token=zxy123

5) The user is now on Tumblr.com and may have to login. Once authenticated with Tumblr they will
will either have to click on allow/deny, or will be automatically redirected back to the callback.

6) Now that the user has returned to callback.php and allowed access we need to build a new
TumblrOAuth object using the temporary credentials.

    $connection = new TumblrOAuth(CONSUMER_KEY, CONSUMER_SECRET, $_REQUEST['oauth_token'], $_REQUEST['oauth_token_secret']);

7) Now we ask Tumblr for long lasting token credentials. These are specific to the application
and user and will act like password to make future requests. Normally the token credentials would
get saved in your database but for this example we are just using sessions.

    $token_credentials = $connection->getAccessToken($_REQUEST['oauth_verifier']);

8) With the token credentials we build a new TumblrOAuth object.

    $connection = new TumblrOAuth(CONSUMER_KEY, CONSUMER_SECRET, $token_credentials['oauth_token'],
    $token_credentials['oauth_token_secret']);

9) And finally we can make requests authenticated as the user. You can GET, POST, and DELETE API
methods. Directly copy the path from the API documentation and add an array of any parameter
you wish to include for the API method.

    $user = $connection->get('user/info');
    $status = $connection->post('{base-hostname}/post', array('type'=>'text','title'=>'Test Title','body'=>'Test body'));
    $status = $connection->post('{base-hostname}/post/delete', array('id'=>123456));

Contributors
============

* [Abraham Williams](https://twitter.com/abraham) - Main developer of TwitterOAuth
* [Rachman Chavik](https://github.com/rchavik) - Source of this fork
* [Maxime Aoustin](https://github.com/maxwell2022) - Myself
