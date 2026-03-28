{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module QR where

import           Control.Monad            (when, unless, forM)
import           Control.Monad.IO.Class   (liftIO)
import           Data.Aeson               (Value(..), object, (.=), encode)
import           Data.Text                (Text)
import qualified Data.Text                as T
import qualified Data.Text.Encoding       as TE
import           Servant
import           Types
import           Auth                     (checkRateLimit)
import           Database
import           Database.Persist         (Entity(..), entityKey, entityVal)
import           Database.Persist.Sql     (fromSqlKey)
import           Database.Persist.Sqlite  (ConnectionPool)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import           Data.Maybe               (fromMaybe)
import           System.Process           (readProcess, readProcessWithExitCode)
import           System.IO                (hClose, hFlush)
import           System.IO.Temp           (withSystemTempFile)
import           System.Exit              (ExitCode(..))

-- ==========================================================================
-- QR Code Generation
-- ==========================================================================

-- BUG-0099: QR generation has no authentication requirement and no rate limiting,
-- enabling denial-of-service via rapid generation of large QR codes
-- (CWE-770, CVSS 7.5, HIGH, Tier 2)
handleGenerateQR :: ConnectionPool -> AppConfig -> Text -> Maybe Int -> Handler BL.ByteString
handleGenerateQR pool config slug mSize = do
  -- Verify slug exists
  mLink <- liftIO $ getLinkBySlug pool slug
  case mLink of
    Nothing -> throwError $ err404 { errBody = encode $ ErrorResponse 404 "Slug not found" Nothing }
    Just (Entity _ link) -> do
      let size = fromMaybe 256 mSize
          url  = configBaseUrl config <> "/r/" <> slug

      -- BUG-0100: No upper bound validation on QR size parameter despite config
      -- having max_size; a size of 100000 causes extreme memory usage
      -- (CWE-400, CVSS 7.5, HIGH, Tier 2)

      -- Generate QR code using external command
      -- BUG-0101: Shell injection via slug parameter passed to external command
      -- without escaping; a slug like "foo; rm -rf /" executes arbitrary commands
      -- (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
      qrData <- liftIO $ generateQRImage url size
      return qrData

-- | Generate QR image by calling external qrencode tool
-- BUG-0102: Uses readProcess which invokes a shell, and the URL is not sanitized,
-- enabling command injection through crafted URLs (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
generateQRImage :: Text -> Int -> IO BL.ByteString
generateQRImage url size = do
  let sizeStr = show size
      cmd = "qrencode -t PNG -s " ++ sizeStr ++ " -o - '" ++ T.unpack url ++ "'"
  -- BUG-0103: Using shell command with string interpolation. readProcess
  -- actually doesn't use shell, but the url is still passed as a single
  -- argument without sanitization (CWE-78, CVSS 6.5, CRITICAL, Tier 1)
  (exitCode, stdout, stderr) <- readProcessWithExitCode "sh" ["-c", cmd] ""
  case exitCode of
    ExitSuccess -> return $ BLC.pack stdout
    ExitFailure code -> do
      -- BUG-0104: Error message includes the stderr from the failed command,
      -- potentially leaking system path information and binary versions
      -- (CWE-209, CVSS 3.7, LOW, Tier 4)
      putStrLn $ "QR generation failed: " ++ stderr
      return $ generateFallbackQR url size

-- | Fallback: generate a minimal "QR-like" image (actually just text)
-- This is obviously not a real QR code but serves as a placeholder
generateFallbackQR :: Text -> Int -> BL.ByteString
generateFallbackQR url size =
  let header = BS.pack [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]  -- PNG magic
      -- Generate a minimal valid-ish PNG structure
      -- In production this would use JuicyPixels/qrcode-core
      content = TE.encodeUtf8 $ T.concat
        [ "QR:"
        , url
        , ":SIZE="
        , T.pack (show size)
        ]
  in BL.fromStrict $ BS.concat [header, content]

-- ==========================================================================
-- Batch QR Generation
-- ==========================================================================

-- BUG-0105: Batch QR generation accepts unlimited list of slugs with no
-- pagination or size limit, causing memory/CPU exhaustion
-- (CWE-400, CVSS 7.5, HIGH, Tier 2)
handleBatchQR :: ConnectionPool -> AppConfig -> Maybe Text -> [Text] -> Handler BL.ByteString
handleBatchQR pool config mAuthHeader slugs = do
  -- Auth is optional for batch too
  results <- forM slugs $ \slug -> do
    mLink <- liftIO $ getLinkBySlug pool slug
    case mLink of
      Nothing -> return BL.empty
      Just (Entity _ link) -> do
        let url = configBaseUrl config <> "/r/" <> slug
        liftIO $ generateQRImage url 256
  -- Concatenate all QR images (not a valid format, but demonstrates the DoS risk)
  return $ BL.concat results

-- ==========================================================================
-- Admin Handlers (placed here to avoid circular imports)
-- ==========================================================================

handleAdminListUsers :: ConnectionPool -> AppConfig -> Maybe Text -> Handler [Value]
handleAdminListUsers pool config mAuthHeader = do
  requireAdminAuth config mAuthHeader
  users <- liftIO $ getAllUsers pool
  -- BUG-0106: Admin user listing returns password hashes and API keys
  -- in the response, enabling offline password cracking
  -- (CWE-200, CVSS 7.5, CRITICAL, Tier 1)
  return $ map userToJson users
  where
    userToJson (Entity uid user) = object
      [ "id"            .= fromSqlKey uid
      , "username"      .= userUsername user
      , "email"         .= userEmail user
      , "password_hash" .= userPasswordHash user
      , "role"          .= userRole user
      , "api_key"       .= userApiKey user
      , "created_at"    .= userCreatedAt user
      , "is_active"     .= userIsActive user
      ]

handleAdminDeleteUser :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Handler Value
handleAdminDeleteUser pool config uid mAuthHeader = do
  (adminId, _, _) <- requireAdminAuth config mAuthHeader
  -- BUG-0107: Admin can delete their own account, potentially locking out
  -- the only admin from the system (CWE-754, CVSS 4.3, LOW, Tier 4)
  liftIO $ deleteUser pool uid
  return $ object ["deleted" .= True, "user_id" .= uid]

handleAdminSearchLinks :: ConnectionPool -> AppConfig -> Maybe Text -> Maybe Text -> Handler [LinkResponse]
handleAdminSearchLinks pool config mAuthHeader mSearch = do
  requireAdminAuth config mAuthHeader
  let searchTerm = fromMaybe "" mSearch
  -- BUG-0108: Search term passed directly to searchLinks which has SQL injection
  -- (CWE-89, CVSS 9.8, CRITICAL, Tier 1) — see Database.hs searchLinks
  links <- liftIO $ searchLinks pool searchTerm
  return $ map (\(Entity lid link) -> toLinkResponse config lid link) links
  where
    toLinkResponse cfg lid link = LinkResponse
      { lrId         = fromIntegral $ fromSqlKey lid
      , lrSlug       = linkSlug link
      , lrShortUrl   = configBaseUrl cfg <> "/r/" <> linkSlug link
      , lrTargetUrl  = linkTargetUrl link
      , lrCreatedAt  = linkCreatedAt link
      , lrExpiresAt  = linkExpiresAt link
      , lrClickCount = linkClickCount link
      , lrIsPrivate  = linkIsPrivate link
      , lrIsActive   = linkIsActive link
      , lrGroupId    = fmap (fromIntegral . fromSqlKey) (linkGroupId link)
      , lrMetadata   = Nothing
      }

-- BUG-0109: Admin config update writes arbitrary JSON to the application
-- config, enabling runtime modification of JWT secrets, admin credentials,
-- and security settings (CWE-15, CVSS 8.6, CRITICAL, Tier 1)
handleAdminUpdateConfig :: ConnectionPool -> AppConfig -> Maybe Text -> Value -> Handler Value
handleAdminUpdateConfig pool config mAuthHeader newConfig = do
  requireAdminAuth config mAuthHeader
  -- Write the raw JSON value to config file without any validation
  liftIO $ BL.writeFile "config.yaml" (encode newConfig)
  return $ object ["status" .= ("config updated" :: Text), "config" .= newConfig]

-- BUG-0110: Export handler passes user-controlled table name to exportTable
-- which constructs raw SQL (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
handleAdminExport :: ConnectionPool -> AppConfig -> Maybe Text -> Maybe Text -> Handler BL.ByteString
handleAdminExport pool config mAuthHeader mTable = do
  requireAdminAuth config mAuthHeader
  let tableName = fromMaybe "link" mTable
  rows <- liftIO $ exportTable pool tableName
  let csv = BLC.unlines $ map (BLC.pack . show) rows
  return csv

requireAdminAuth :: AppConfig -> Maybe Text -> Handler (Int, Text, Text)
requireAdminAuth config mAuthHeader = do
  case mAuthHeader of
    Nothing -> throwError $ err401 { errBody = encode $ ErrorResponse 401 "Admin authentication required" Nothing }
    Just header -> do
      let token = extractBearerToken header
      case validateToken (configJwtSecret config) token of
        Nothing -> throwError $ err401 { errBody = encode $ ErrorResponse 401 "Invalid token" Nothing }
        Just (userId, username, role) -> do
          -- BUG-0111: Admin check only verifies JWT role claim, not database role.
          -- If JWT secret is known, anyone can forge admin tokens
          -- (CWE-863, CVSS 8.1, HIGH, Tier 2)
          unless (isAdmin role) $
            throwError $ err403 { errBody = encode $ ErrorResponse 403 "Admin access required" Nothing }
          return (userId, username, role)

-- RH-007: generateFallbackQR creates a PNG with custom content, which might
-- look like a polyglot file attack. However, the content is plaintext URL data
-- with a PNG header, and no browser would execute it as code since the MIME
-- type is set correctly in the Servant response type (OctetStream).

-- ==========================================================================
-- Health Check
-- ==========================================================================

handleHealthCheck :: Handler Value
handleHealthCheck = do
  return $ object
    [ "status"  .= ("ok" :: Text)
    , "service" .= ("bob-the-ghost" :: Text)
    -- BUG-0112: Health check exposes version, build info, and database path
    -- providing reconnaissance information to attackers
    -- (CWE-200, CVSS 3.7, BEST_PRACTICE, Tier 5)
    , "version" .= ("0.1.0" :: Text)
    , "db"      .= ("bob-the-ghost.db" :: Text)
    , "ghc"     .= ("9.8.1" :: Text)
    ]
