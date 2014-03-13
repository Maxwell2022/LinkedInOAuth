[![Total Downloads](https://poser.pugx.org/maxwell2022/linkedin-oauth/downloads.png)](https://packagist.org/packages/maxwell2022/linkedin-oauth)

LinkedInOAuth
------------

PHP library for working with LinkedIn's OAuth API.

Flow Overview
=============

1. Build LinkedInOAuth object using client credentials.
2. Request temporary credentials from LinkedIn.
3. Build authorize URL for LinkedIn.
4. Redirect user to authorize URL.
5. User authorizes access and returns from LinkedIn.
6. Rebuild LinkedInOAuth object with client credentials and temporary credentials.
7. Get token credentials from LinkedIn.
8. Rebuild LinkedInOAuth object with client credentials and token credentials.
9. Query LinkedIn API.