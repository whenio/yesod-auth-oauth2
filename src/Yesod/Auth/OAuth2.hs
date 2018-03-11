{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
-- |
--
-- Generic OAuth2 plugin for Yesod
--
-- See @"Yesod.Auth.OAuth2.GitHub"@ for example usage.
--
module Yesod.Auth.OAuth2
    ( OAuth2(..)
    , FetchCreds
    , Manager
    , OAuth2Token(..)
    , Creds(..)
    , oauth2Url
    , authOAuth2
    , authOAuth2Widget

    -- * Reading our @'credsExtra'@ keys
    , getAccessToken
    , getRefreshToken
    , getExpiresIn
    , getUserResponse
    , getUserResponseJSON
    ) where

import Control.Error.Util (note)
import Control.Monad ((<=<))
import Data.Aeson (FromJSON, eitherDecode)
import Data.ByteString.Lazy (ByteString, fromStrict)
import Data.Text (Text, unpack)
import Data.Text.Encoding (encodeUtf8)
import Network.HTTP.Conduit (Manager)
import Network.OAuth.OAuth2
import Yesod.Auth
import Yesod.Auth.OAuth2.Dispatch
import Yesod.Core.Widget

oauth2Url :: Text -> AuthRoute
oauth2Url name = PluginR name ["forward"]

-- | Create an @'AuthPlugin'@ for the given OAuth2 provider
--
-- Presents a generic @"Login via #{name}"@ link
--
authOAuth2 :: YesodAuth m => Text -> OAuth2 -> FetchCreds m -> AuthPlugin m
authOAuth2 name = authOAuth2Widget [whamlet|Login via #{name}|] name

-- | Create an @'AuthPlugin'@ for the given OAuth2 provider
--
-- Allows passing a custom widget for the login link. See @'oauth2Eve'@ for an
-- example.
--
authOAuth2Widget
    :: YesodAuth m
    => WidgetFor m ()
    -> Text
    -> OAuth2
    -> FetchCreds m
    -> AuthPlugin m
authOAuth2Widget widget name oauth getCreds =
    AuthPlugin name (dispatchAuthRequest name oauth getCreds) login
  where
    login tm = [whamlet|<a href=@{tm $ oauth2Url name}>^{widget}|]

-- | Read the @'AccessToken'@ from the values set via @'setExtra'@
getAccessToken :: Creds m -> Maybe AccessToken
getAccessToken =
    (AccessToken <$>) . lookup "accessToken" . credsExtra

getExtraValue :: (Text -> a) -> Text -> Creds m -> Maybe a
getExtraValue constructor extraKey =
    (constructor <$>) . lookup extraKey . credsExtra

-- | Read from the values set via @'setExtra'@
getExpiresIn :: Creds m -> Maybe Int
getExpiresIn = fmap (read . unpack) . lookup "expiresIn" . credsExtra

-- | Read the @'RefreshToken'@ from the values set via @'setExtra'@
--
-- N.B. not all providers supply this value.
--
getRefreshToken :: Creds m -> Maybe RefreshToken
getRefreshToken =
    (RefreshToken <$>) . lookup "refreshToken" . credsExtra

-- | Read the original profile response from the values set via @'setExtra'@
getUserResponse :: Creds m -> Maybe ByteString
getUserResponse =
    (fromStrict . encodeUtf8 <$>) . lookup "userResponse" . credsExtra

-- | @'getUserResponse'@, and decode as JSON
getUserResponseJSON :: FromJSON a => Creds m -> Either String a
getUserResponseJSON =
    eitherDecode <=< note "userResponse key not present" . getUserResponse
