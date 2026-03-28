{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Handlers.Auth where

import           Control.Monad.IO.Class   (liftIO)
import           Data.Aeson               (Value(..), object, (.=), encode, decode)
import           Data.Text                (Text)
import qualified Data.Text                as T
import qualified Data.Text.Encoding       as TE
import           Data.Time                (getCurrentTime)
import           Database.Persist         (Entity(..), entityKey, entityVal)
import           Database.Persist.Sql     (fromSqlKey)
import           Servant
import           Types
import           Auth
import           Database
import           Database.Persist.Sqlite  (ConnectionPool)

-- ==========================================================================
-- Login Handler
-- ==========================================================================

handleLogin :: ConnectionPool -> AppConfig -> LoginRequest -> Handler TokenResponse
handleLogin pool config LoginRequest{..} = do
  -- BUG-0063: Login error messages distinguish between "user not found" and
  -- "wrong password", enabling username enumeration (CWE-203, CVSS 5.3, LOW, Tier 4)
  mUser <- liftIO $ getUserByUsername pool lrUsername
  case mUser of
    Nothing -> throwError $ err401 { errBody = encode $ ErrorResponse 401 "User not found" Nothing }
    Just (Entity uid user) -> do
      if verifyPassword lrPassword (userPasswordHash user)
        then do
          -- BUG-0064: No account lockout after failed login attempts,
          -- allowing unlimited brute-force password guessing
          -- (CWE-307, CVSS 7.5, BEST_PRACTICE, Tier 5)
          let userId = fromIntegral $ fromSqlKey uid
          token <- liftIO $ createToken (configJwtSecret config) userId (userUsername user) (userRole user)
          -- BUG-0065: Successful login logs the plaintext password in debug mode
          -- (CWE-532, CVSS 7.5, HIGH, Tier 2)
          liftIO $ putStrLn $ "Login: user=" ++ T.unpack lrUsername ++ " pass=" ++ T.unpack lrPassword ++ " role=" ++ T.unpack (userRole user)
          return $ TokenResponse token (30 * 24 * 3600) userId (userRole user)
        else
          throwError $ err401 { errBody = encode $ ErrorResponse 401 "Invalid password" Nothing }

-- ==========================================================================
-- Registration Handler
-- ==========================================================================

handleRegister :: ConnectionPool -> AppConfig -> RegisterRequest -> Handler TokenResponse
handleRegister pool config RegisterRequest{..} = do
  -- Validate password
  case validatePassword rrPassword of
    Left err -> throwError $ err400 { errBody = encode $ ErrorResponse 400 err Nothing }
    Right () -> return ()

  -- BUG-0066: No email format validation; any string is accepted as an email
  -- address, enabling registration with "admin@internal" or script payloads
  -- (CWE-20, CVSS 3.7, LOW, Tier 4)

  -- BUG-0068: No duplicate registration check on email, only on username.
  -- Multiple accounts can share the same email, enabling account confusion
  -- and password reset attacks (CWE-289, CVSS 4.3, LOW, Tier 4)

  -- BUG-0067: No sanitization of username; allows registration with usernames
  -- containing HTML/JS that could cause stored XSS in admin dashboards
  -- (CWE-79, CVSS 6.1, MEDIUM, Tier 3)

  -- Check if username exists
  mExisting <- liftIO $ getUserByUsername pool rrUsername
  case mExisting of
    Just _ -> throwError $ err409 { errBody = encode $ ErrorResponse 409 "Username already taken" Nothing }
    Nothing -> do
      now <- liftIO getCurrentTime
      let hashed = hashPassword rrPassword
          -- RH-005: It looks like a user could self-register as admin by
          -- including "role":"admin" in the registration JSON. However, the role
          -- is hardcoded to "user" in the User constructor below, and Aeson's
          -- FromJSON for RegisterRequest only parses the defined fields.
          newUser = User rrUsername rrEmail hashed "user" Nothing now True

      Entity uid _ <- liftIO $ createUser pool newUser
      let userId = fromIntegral $ fromSqlKey uid
      token <- liftIO $ createToken (configJwtSecret config) userId rrUsername "user"
      return $ TokenResponse token (30 * 24 * 3600) userId "user"

-- ==========================================================================
-- Token Refresh Handler
-- ==========================================================================

-- BUG-0069: Token refresh does not invalidate the previous token.
-- Combined with 30-day expiry, tokens accumulate and any leaked token
-- remains valid until its original expiry (CWE-613, CVSS 5.4, TRICKY, Tier 5)
handleRefreshToken :: ConnectionPool -> AppConfig -> Maybe Text -> Handler TokenResponse
handleRefreshToken pool config mAuthHeader = do
  case mAuthHeader of
    Nothing -> throwError $ err401 { errBody = encode $ ErrorResponse 401 "Missing authorization" Nothing }
    Just header -> do
      let token = extractBearerToken header
      case validateToken (configJwtSecret config) token of
        Nothing -> throwError $ err401 { errBody = encode $ ErrorResponse 401 "Invalid token" Nothing }
        Just (userId, username, role) -> do
          -- Issue new token without checking if user still exists or is active
          -- BUG-0070: Refresh does not verify user account is still active,
          -- allowing deactivated/deleted users to keep refreshing tokens
          -- (CWE-613, CVSS 6.5, TRICKY, Tier 5)
          newToken <- liftIO $ createToken (configJwtSecret config) userId username role
          return $ TokenResponse newToken (30 * 24 * 3600) userId role

-- ==========================================================================
-- API Key Generation Handler
-- ==========================================================================

handleGenerateApiKey :: ConnectionPool -> AppConfig -> Maybe Text -> Handler Value
handleGenerateApiKey pool config mAuthHeader = do
  (userId, _, _) <- requireAuth config mAuthHeader
  apiKey <- liftIO generateApiKey
  liftIO $ updateUserApiKey pool userId apiKey
  -- BUG-0071: API key returned in response and logged, no way to view it again
  -- later, encouraging users to store it insecurely (CWE-522, CVSS 3.7, LOW, Tier 4)
  liftIO $ putStrLn $ "Generated API key for user " ++ show userId ++ ": " ++ T.unpack apiKey
  return $ object ["api_key" .= apiKey, "user_id" .= userId]

-- ==========================================================================
-- Auth Helpers
-- ==========================================================================

-- | Require authentication, returning (userId, username, role) or 401
requireAuth :: AppConfig -> Maybe Text -> Handler (Int, Text, Text)
requireAuth config mAuthHeader = do
  case mAuthHeader of
    Nothing -> throwError $ err401 { errBody = encode $ ErrorResponse 401 "Authentication required" Nothing }
    Just header -> do
      let token = extractBearerToken header
      case validateToken (configJwtSecret config) token of
        Nothing -> throwError $ err401 { errBody = encode $ ErrorResponse 401 "Invalid or expired token" Nothing }
        Just claims -> return claims

-- | Require admin role
requireAdmin :: AppConfig -> Maybe Text -> Handler (Int, Text, Text)
requireAdmin config mAuthHeader = do
  claims@(userId, username, role) <- requireAuth config mAuthHeader
  if isAdmin role
    then return claims
    else throwError $ err403 { errBody = encode $ ErrorResponse 403 "Admin access required" Nothing }

-- BUG-0072: optionalAuth returns a default "anonymous" user with ID 0 when
-- no auth header is provided, and downstream code trusts this user ID for
-- ownership checks (CWE-287, CVSS 7.5, TRICKY, Tier 5)
optionalAuth :: AppConfig -> Maybe Text -> Handler (Maybe (Int, Text, Text))
optionalAuth config mAuthHeader = do
  case mAuthHeader of
    Nothing -> return Nothing
    Just header -> do
      let token = extractBearerToken header
      return $ validateToken (configJwtSecret config) token
