module Twitter where

  import OAuth

  oauthAuthorizeUrl = "http://api.twitter.com/oauth/authorize"
  statusesUpdateUrl = "http://api.twitter.com/1/statuses/update.json"

  updateStatus consumer accessToken text =
      do sendOAuthRequest statusesUpdateUrl params oauthParams (secret accessToken) consumer
    where params      = [("status", text)]
          oauthParams = [("oauth_token", (token accessToken))] 

