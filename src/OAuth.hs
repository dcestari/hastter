module OAuth where

  import Network.HTTP
  import Data.Time
  import Data.Time.LocalTime
  import Data.Time.Clock.POSIX

  import qualified Data.List as DL
  import qualified Data.List.Split as DLS
  import qualified Data.HMAC as DH
  import qualified Data.ByteString.Internal as BS
  import qualified Text.Printf as PF
  import qualified Data.Word as DW
  import qualified Codec.Binary.Base64 as Base64
  import qualified Data.Digest.SHA256 as DS
  import qualified System.Random as R

  data Consumer = Consumer { consumerKey :: String, consumerSecret :: String } deriving (Show, Eq)
  data TokenData    = Token { token :: String, secret :: String } deriving (Show, Eq)
  type AccessToken  = TokenData
  type RequestToken = TokenData

  signRequest httpMethod baseUri params tokenSecret consumer = Base64.encode binary_hash
    where sorted_params = DL.sortBy (\x@(a,_) y@(b,_) -> compare a b) params
          params_string = map (\(k, v) -> (urlEncode k) ++ "=" ++ (urlEncode v)) sorted_params
          query_string  = DL.intercalate "&" params_string
          target_string = DL.intercalate "&" . map urlEncode $ [httpMethod, baseUri, query_string]
          target_word8  = map BS.c2w target_string
          secret_word8  = map BS.c2w $ (consumerSecret consumer) ++ "&" ++ tokenSecret
          binary_hash   = DH.hmac_sha1 secret_word8 target_word8
          
  toHexString :: [DW.Word8] -> String
  toHexString = concatMap (\x -> PF.printf "%0.2x" x)

  replace _ _ [] = []
  replace target replacement text = if chunk == target then replacement ++ next else chunk ++ next
    where chunk = take (length target) text
          rest  = drop (length target) text
          next  = replace target replacement rest

  encodeRFC3986 :: String -> String
  encodeRFC3986 txt = replace "%7E" "~" $ replace "+" " " txt

  getUnixTime :: IO Int
  getUnixTime = getPOSIXTime >>= return . floor

  generateOAuthNonce time g = toHexString . DS.hash $ map BS.c2w seed
    where onlyFirst = \(r,_) -> r
          rdm = show $ onlyFirst $ R.next g
          seed = rdm ++ (show time)

  getOAuthString method url time g extraParams oauthParams tokenSecret consumer = oauth_query
    where oauth_consumer_key     = ("oauth_consumer_key", (consumerKey consumer))
          oauth_nonce            = ("oauth_nonce", generateOAuthNonce time g)
          oauth_timestamp        = ("oauth_timestamp", (show time))
          oauth_version          = ("oauth_version", "1.0")
          oauth_signature_method = ("oauth_signature_method", "HMAC-SHA1")
          params      = oauthParams ++ [oauth_consumer_key, oauth_nonce, oauth_timestamp, oauth_version, oauth_signature_method]
          signature   = signRequest method url (extraParams ++ params) tokenSecret consumer
          new_params  = ("oauth_signature", signature) : params
          oauth_query = DL.intercalate ", " $ map (\(k, v) -> k ++ "=\"" ++ (urlEncode v) ++ "\"") new_params          

  postOAuthRequest url time gen params oauthParams tokenSecret consumer = insertHeader HdrAuthorization oauth_string req
    where request_body = DL.intercalate "&" $ map (\(k, v) -> k ++ "=" ++ (urlEncode v)) params
          preReq = (postRequest url) { rqBody = request_body }
          req    = replaceHeader HdrContentLength (show $ length request_body) preReq
          oauth_string = "OAuth realm=\"" ++ url ++ "\", " ++ (getOAuthString "POST" url time gen params oauthParams tokenSecret consumer)

  parseQueryString txt = map parseParam parts
    where parts = DLS.unintercalate "&" txt
          parseParam = \t -> let a = DLS.unintercalate "=" t in (head a, head . tail $ a)

  extractTokens txt = (key, secret)
    where params = parseQueryString txt
          key    = extractParam "oauth_token" params
          secret = extractParam "oauth_token_secret" params
  
  extractParam _ [] = Nothing
  extractParam p ((k,v):params)
    | p == k    = Just v
    | otherwise = extractParam p params

  containsParam _ [] = False
  containsParam p ((k,v):params) = p == k || containsParam p params

  buildToken :: String -> Maybe TokenData
  buildToken s =
      case (a, b) of
        (Just tokenKey, Just tokenSecret) -> Just $ Token { token = tokenKey, secret = tokenSecret }
        _ -> Nothing
    where (a, b) = extractTokens s

  sendOAuthRequest url params oauthParams tokenSecret consumer =
    do ts  <- getUnixTime
       gen  <- R.newStdGen
       print ("time is: " ++ (show ts))
       let request = postOAuthRequest url ts gen params oauthParams tokenSecret consumer
       print request
       rsp  <- simpleHTTP request
       print rsp
       body <- getResponseBody rsp
       return body

  getRequestToken :: Consumer -> IO (Maybe RequestToken)
  getRequestToken consumer =
      do body <- sendOAuthRequest "http://api.twitter.com/oauth/request_token" [] oauthParams "" consumer
         return (buildToken body)
    where oauth_callback = ("oauth_callback", "oob")
          oauthParams    = [oauth_callback]

  getAccessToken consumer verifier requestToken =
      do body <- sendOAuthRequest "http://api.twitter.com/oauth/access_token" [] oauthParams (secret requestToken) consumer
         return (buildToken body)
    where oauth_token    = ("oauth_token", (token requestToken))
          oauth_verifier = ("oauth_verifier", verifier)
          oauthParams    = [oauth_token, oauth_verifier] 

