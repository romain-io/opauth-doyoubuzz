Opauth-DoYouBuzz
=============
Opauth strategy for DoYouBuzz authentification

Implemented based on http://doc.doyoubuzz.com/dyb/oauth

Getting started
---------------
```bash
cd path_to_opauth/Strategy
git clone https://github.com/rockshappy/opauth-doyoubuzz.git DoYouBuzz
```


Strategy configuration
----------------------

Required parameters:

```php
<?php
'OAuth' => array(
	'consumer_key' => 'YOUR CONSUMER KEY',
	'consumer_secret' => 'YOUR CONSUMER SECRET',

	'request_token_url' => 'http://OAUTH_SERVER/oauth/request_token',
	'access_token_url' => 'http://OAUTH_SERVER/oauth/access_token'
)
```

See OAuth.php for optional parameters.

Dependencies
------------
tmhOAuth requires hash_hmac and cURL.  
hash_hmac is available on PHP 5 >= 5.1.2.

Reference
---------
 - [OAuth Core 1.0](http://oauth.net/core/1.0/)

License
---------
Opauth-OAuth is MIT Licensed  
Copyright © 2012 U-Zyn Chua (http://uzyn.com)

tmhOAuth is [Apache 2 licensed](https://github.com/themattharris/tmhOAuth/blob/master/LICENSE).

[1]: https://github.com/uzyn/opauth