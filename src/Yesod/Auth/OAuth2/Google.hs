{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
-- |
--
-- OAuth2 plugin for http://www.google.com
--
-- * Authenticates against Google
-- * Uses Google user id as credentials identifier
--
-- If you were previously relying on email as the creds identifier, you can
-- still do that (and more) by overriding it in the creds returned by the plugin
-- with any value read out of the new @userResponse@ key in @'credsExtra'@.
--
-- For example:
--
-- > data User = User { userEmail :: Text }
-- >
-- > instance FromJSON User where -- you know...
-- >
-- > authenticate creds = do
-- >     -- 'getUserResponseJSON' provided by "Yesod.Auth.OAuth" module
-- >     let Right email = userEmail <$> getUserResponseJSON creds
-- >         updatedCreds = creds { credsIdent = email }
-- >
-- >     -- continue normally with updatedCreds
--
module Yesod.Auth.OAuth2.Google
    ( oauth2Google
    , oauth2GoogleScoped
    , oauth2GoogleScopedOffline
    ) where

import Yesod.Auth.OAuth2.Prelude
import Data.ByteString.Char8 (ByteString, pack)

newtype User = User Text

instance FromJSON User where
    parseJSON = withObject "User" $ \o -> User
        -- Required for data backwards-compatibility
        <$> (("google-uid:" <>) <$> o .: "sub")

data AccessType = Online | Offline

instance Show AccessType where
  show Online  = "online"
  show Offline = "offline"

pluginName :: Text
pluginName = "google"

defaultScopes :: [Text]
defaultScopes = ["openid", "email"]

accessTypeParam :: AccessType -> (ByteString, ByteString)
accessTypeParam = ("access_type",) . pack . show

oauth2Google :: YesodAuth m => Text -> Text -> AuthPlugin m
oauth2Google = oauth2GoogleScoped defaultScopes

oauth2GoogleScoped :: YesodAuth m => [Text] -> Text -> Text -> AuthPlugin m
oauth2GoogleScoped = oauth2GoogleScopedWithAccessType Online

oauth2GoogleScopedOffline :: YesodAuth m => [Text] -> Text -> Text -> AuthPlugin m
oauth2GoogleScopedOffline = oauth2GoogleScopedWithAccessType Offline

oauth2GoogleScopedWithAccessType :: YesodAuth m
                                 => AccessType
                                 -> [Text]
                                 -> Text
                                 -> Text
                                 -> AuthPlugin m
oauth2GoogleScopedWithAccessType accessType scopes clientId clientSecret =
    authOAuth2 pluginName oauth2 $ \manager token -> do
        (User userId, userResponse) <-
            authGetProfile pluginName manager token "https://www.googleapis.com/oauth2/v3/userinfo"

        pure Creds
            { credsPlugin = pluginName
            , credsIdent = userId
            , credsExtra = setExtra token userResponse
            }
  where
    oauth2 = OAuth2
        { oauthClientId = clientId
        , oauthClientSecret = clientSecret
        , oauthOAuthorizeEndpoint = "https://accounts.google.com/o/oauth2/auth" `withQuery`
            [ scopeParam " " scopes
            , accessTypeParam accessType
            ]
        , oauthAccessTokenEndpoint = "https://www.googleapis.com/oauth2/v3/token"
        , oauthCallback = Nothing
        }
