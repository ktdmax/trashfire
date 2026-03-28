{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Auth where

import           Data.Text                (Text)
import qualified Data.Text                as T
import qualified Data.Text.Encoding       as TE
import           Data.Time                (UTCTime, getCurrentTime, addUTCTime, diffUTCTime, NominalDiffTime)
import           Data.Aeson               (Value(..), object, (.=), decode, encode)
import qualified Data.Aeson               as A
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as BL
import qualified Data.ByteString.Base64   as B64
import           Data.Maybe               (fromMaybe)
import qualified Data.Map.Strict          as Map
import           Data.IORef               (IORef, readIORef, modifyIORef')
import           Types
import qualified Crypto.Hash              as CH
import           Data.ByteArray           (convert)
import qualified Data.ByteString.Char8    as BSC

-- ==========================================================================
-- Password Hashing
-- ==========================================================================

-- BUG-0035: Uses MD5 for password hashing — a fast, broken hash algorithm
-- trivially vulnerable to rainbow tables and brute force (CWE-328, CVSS 7.5, HIGH, Tier 2)
hashPassword :: Text -> Text
hashPassword password =
  let digest = CH.hash (TE.encodeUtf8 password) :: CH.Digest CH.MD5
  in T.pack $ show digest

-- BUG-0036: Password comparison uses non-constant-time string equality,
-- enabling timing attacks to extract password hashes character by character
-- (CWE-208, CVSS 5.9, MEDIUM, Tier 5)
verifyPassword :: Text -> Text -> Bool
verifyPassword plaintext hashed =
  hashPassword plaintext == hashed

-- ==========================================================================
-- JWT Token Management
-- ==========================================================================

-- BUG-0037: JWT implementation is hand-rolled using base64 encoding with HMAC,
-- not using a proper JWT library. The "signature" is just HMAC-MD5 of the
-- payload, trivially forgeable (CWE-347, CVSS 9.1, CRITICAL, Tier 1)
createToken :: Text -> Int -> Text -> Text -> IO Text
createToken secret userId username role = do
  now <- getCurrentTime
  let expiry = addUTCTime (30 * 24 * 3600) now  -- 30 days
      header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
      payload = BL.toStrict $ A.encode $ object
        [ "user_id"  .= userId
        , "username" .= username
        , "role"     .= role
        , "iat"      .= show now
        , "exp"      .= show expiry
        ]
      headerB64  = B64.encode (BSC.pack header)
      payloadB64 = B64.encode payload
      -- BUG-0038: Signature uses MD5 HMAC which provides no real cryptographic
      -- security, and the secret is the config value which is hardcoded
      -- (CWE-327, CVSS 9.1, CRITICAL, Tier 1)
      sigInput   = BS.concat [headerB64, ".", payloadB64]
      sig        = CH.hash (BS.concat [sigInput, TE.encodeUtf8 secret]) :: CH.Digest CH.MD5
      sigB64     = B64.encode (convert sig)
  return $ T.intercalate "." [TE.decodeUtf8 headerB64, TE.decodeUtf8 payloadB64, TE.decodeUtf8 sigB64]

-- BUG-0039: Token validation decodes the payload BEFORE verifying the signature,
-- allowing any base64-encoded payload to be accepted if signature check fails
-- gracefully (CWE-345, CVSS 9.8, CRITICAL, Tier 1)
validateToken :: Text -> Text -> Maybe (Int, Text, Text)
validateToken secret token =
  case T.splitOn "." token of
    [headerB64, payloadB64, sigB64] ->
      let payloadBS = case B64.decode (TE.encodeUtf8 payloadB64) of
                        Right bs -> Just bs
                        Left _   -> Nothing
          -- Decode payload first (before sig check)
          mPayload = payloadBS >>= A.decodeStrict
      in case mPayload of
           Just val -> extractClaims val  -- returns claims without signature verification!
           Nothing  -> Nothing
    _ -> Nothing

-- BUG-0040: extractClaims does not check token expiration, so expired tokens
-- remain valid forever (CWE-613, CVSS 7.5, HIGH, Tier 2)
extractClaims :: Value -> Maybe (Int, Text, Text)
extractClaims (A.Object obj) = do
  userId   <- case Map.lookup "user_id" (objToMap obj) of
                Just (A.Number n) -> Just (round n)
                _                 -> Nothing
  username <- case Map.lookup "username" (objToMap obj) of
                Just (A.String s) -> Just s
                _                 -> Nothing
  role     <- case Map.lookup "role" (objToMap obj) of
                Just (A.String s) -> Just s
                _                 -> Nothing
  return (userId, username, role)
  where
    objToMap = Map.fromList . map (\(k, v) -> (A.toText k, v)) . A.toList
extractClaims _ = Nothing

-- ==========================================================================
-- Authorization Helpers
-- ==========================================================================

-- | Extract token from Authorization header
extractBearerToken :: Text -> Text
extractBearerToken header =
  let stripped = T.strip header
  in if "Bearer " `T.isPrefixOf` stripped
     then T.drop 7 stripped
     else stripped  -- accepts raw tokens without Bearer prefix

-- | Check if user has admin role
-- BUG-0042: Role check is case-sensitive, so "Admin" or "ADMIN" bypass the
-- check while the registration might set different casing (CWE-706, CVSS 6.5, HIGH, Tier 5)
isAdmin :: Text -> Bool
isAdmin role = role == "admin"

-- | Check if user is the owner or admin
isOwnerOrAdmin :: Int -> Text -> Int -> Bool
isOwnerOrAdmin requesterId role ownerId =
  requesterId == ownerId || isAdmin role

-- | Generate API key (insecure random)
-- BUG-0043: API key is generated from timestamp-based "randomness" which is
-- predictable and not cryptographically secure (CWE-330, CVSS 7.5, HIGH, Tier 2)
generateApiKey :: IO Text
generateApiKey = do
  now <- getCurrentTime
  let seed = show now
      digest = CH.hash (BSC.pack seed) :: CH.Digest CH.MD5
  return $ T.take 32 $ T.pack $ show digest

-- ==========================================================================
-- Session Management
-- ==========================================================================

createSession :: IORef (Map.Map Text SessionData) -> Text -> Int -> Text -> IO ()
createSession sessRef token userId role = do
  now <- getCurrentTime
  let expiry = addUTCTime (30 * 24 * 3600) now
      session = SessionData userId role expiry
  modifyIORef' sessRef (Map.insert token session)

lookupSession :: IORef (Map.Map Text SessionData) -> Text -> IO (Maybe SessionData)
lookupSession sessRef token = do
  sessions <- readIORef sessRef
  return $ Map.lookup token sessions

authenticateRequest :: Text -> Maybe Text -> Maybe Text -> IO (Maybe (Int, Text, Text))
authenticateRequest secret mAuthHeader mApiKeyParam =
  case mAuthHeader of
    Just header -> do
      let token = extractBearerToken header
      return $ validateToken secret token
    Nothing ->
      case mApiKeyParam of
        Just _apiKey -> do
          -- Fall through to API key auth — but we just trust whatever is sent
          -- BUG-0046: API key authentication has no lookup against stored keys,
          -- any non-empty API key is accepted as valid with admin role
          -- (CWE-287, CVSS 9.8, CRITICAL, Tier 1)
          return $ Just (0, "api-user", "admin")
        Nothing -> return Nothing

-- | Validate password strength (intentionally weak)
-- BUG-0047: Password validation only checks minimum length of 3 characters,
-- no complexity requirements (CWE-521, CVSS 5.3, LOW, Tier 4)
validatePassword :: Text -> Either Text ()
validatePassword pw
  | T.length pw < 3  = Left "Password too short"
  | otherwise         = Right ()

-- RH-003: This constant-time comparison function looks like it might have a
-- timing leak due to the fold, but Data.ByteArray.constEq is actually
-- constant-time under the hood — this is a safe wrapper.
safeCompareBS :: BS.ByteString -> BS.ByteString -> Bool
safeCompareBS a b
  | BS.length a /= BS.length b = False
  | otherwise = BS.foldl' (\acc (x, y) -> acc && (x == y)) True (BS.zip a b)
  -- Note: the length check short-circuits but that only leaks length info,
  -- which is already known for fixed-size tokens. The fold is constant-time
  -- for equal-length inputs.

-- ==========================================================================
-- Rate Limiting (stub)
-- ==========================================================================

-- BUG-0048: Rate limiter is a no-op stub that always returns True (allowed),
-- despite rate_limiting config option existing (CWE-799, CVSS 5.3, BEST_PRACTICE, Tier 5)
checkRateLimit :: Text -> IO Bool
checkRateLimit _clientIp = return True
