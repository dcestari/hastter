module Main where

  import OAuth
  import qualified Twitter
  import System.IO

  main :: IO ()
  main =
    do let consumer = Consumer { consumerKey = "YOUR CONSUMER KEY", consumerSecret = "YOUR CONSUMER SECRET" }
       readConfigFile
       requestToken <- getRequestToken consumer
       let (Just rt) = requestToken
       putStrLn $ "Go here: " ++ Twitter.oauthAuthorizeUrl ++ "?oauth_token=" ++ (token rt)
       putStr "Enter PIN: "
       hFlush stdout
       verifier <- getLine
       accessToken <- getAccessToken consumer verifier rt
       let (Just at) = accessToken
       putStr "Status: "
       hFlush stdout
       status <- getLine
       print accessToken
       b <- Twitter.updateStatus consumer at status
       print b

