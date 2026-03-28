{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Handlers.Links where

import           Control.Monad            (when, unless, forM)
import           Control.Monad.IO.Class   (liftIO)
import           Data.Aeson               (Value(..), object, (.=), encode, toJSON)
import qualified Data.Aeson               as A
import           Data.Text                (Text)
import qualified Data.Text                as T
import qualified Data.Text.Encoding       as TE
import           Data.Time                (getCurrentTime, UTCTime)
import           Database.Persist         (Entity(..), entityKey, entityVal, (=.))
import           Database.Persist.Sql     (fromSqlKey, toSqlKey)
import           Servant
import           System.Random            (randomRs, newStdGen)
import           Types
import           Auth
import           Database
import           Handlers.Auth            (requireAuth, optionalAuth, requireAdmin)
import           Database.Persist.Sqlite  (ConnectionPool)
import           Data.Maybe               (fromMaybe, isNothing, isJust)
import qualified Data.ByteString.Lazy     as BL

-- ==========================================================================
-- Link Creation
-- ==========================================================================

handleCreateLink :: ConnectionPool -> AppConfig -> Maybe Text -> CreateLinkRequest -> Handler LinkResponse
handleCreateLink pool config mAuthHeader CreateLinkRequest{..} = do
  mAuth <- liftIO $ authenticateRequest (configJwtSecret config) mAuthHeader Nothing
  -- BUG-0073: Link creation allowed without authentication when auth header
  -- is missing; falls through to anonymous link creation with no owner
  -- (CWE-862, CVSS 5.3, BEST_PRACTICE, Tier 5)
  let mOwnerId = case mAuth of
        Just (uid, _, _) -> Just uid
        Nothing          -> Nothing

  -- Validate target URL
  -- BUG-0074: URL validation only checks for presence of "://" which allows
  -- javascript://anything, data://payload, and file:///etc/passwd URLs
  -- (CWE-601, CVSS 8.1, CRITICAL, Tier 1)
  unless (T.isInfixOf "://" clrTargetUrl) $
    throwError $ err400 { errBody = encode $ ErrorResponse 400 "Invalid URL format" Nothing }

  -- Generate or validate slug
  slug <- case clrCustomSlug of
    Just customSlug -> do
      -- BUG-0076: Custom slug not sanitized — allows path traversal characters
      -- like "../" and URL-encoded payloads that break routing
      -- (CWE-22, CVSS 5.3, MEDIUM, Tier 3)
      existing <- liftIO $ getLinkBySlug pool customSlug
      case existing of
        Just _ -> throwError $ err409 { errBody = encode $ ErrorResponse 409 "Slug already taken" Nothing }
        Nothing -> return customSlug
    Nothing -> liftIO $ generateSlug pool (configSlugLength config)

  now <- liftIO getCurrentTime

  -- BUG-0077: Private token for private links is just the first 8 chars of
  -- the slug reversed, easily guessable (CWE-330, CVSS 6.5, TRICKY, Tier 5)
  let privateToken = if clrIsPrivate
                     then Just $ T.reverse $ T.take 8 $ slug <> "00000000"
                     else Nothing

  let ownerKey = fmap (\uid -> toSqlKey (fromIntegral uid) :: UserId) mOwnerId
      groupKey = fmap (\gid -> toSqlKey (fromIntegral gid) :: LinkGroupId) clrGroupId
      metaText = fmap (TE.decodeUtf8 . BL.toStrict . A.encode) clrMetadata
      newLink = Link
        { linkSlug         = slug
        , linkTargetUrl    = clrTargetUrl
        , linkOwnerId      = ownerKey
        , linkCreatedAt    = now
        , linkExpiresAt    = clrExpiresAt
        , linkIsPrivate    = clrIsPrivate
        , linkPrivateToken = privateToken
        , linkClickCount   = 0
        , linkMaxClicks    = clrMaxClicks
        , linkGroupId      = groupKey
        , linkMetadata     = metaText
        , linkIsActive     = True
        }

  Entity lid link <- liftIO $ createLink pool newLink
  return $ toLinkResponse config lid link

-- ==========================================================================
-- Link Listing
-- ==========================================================================

-- BUG-0078: When no auth header is provided, returns ALL links instead of
-- returning 401, exposing every shortened URL and its target
-- (CWE-862, CVSS 7.5, CRITICAL, Tier 1)
handleListLinks :: ConnectionPool -> AppConfig -> Maybe Text -> Handler [LinkResponse]
handleListLinks pool config mAuthHeader = do
  mAuth <- liftIO $ authenticateRequest (configJwtSecret config) mAuthHeader Nothing
  links <- case mAuth of
    Just (uid, _, role) ->
      if isAdmin role
        then liftIO $ getAllLinks pool
        else liftIO $ getUserLinks pool uid
    Nothing -> liftIO $ getAllLinks pool  -- returns everything for unauthenticated users!
  return $ map (\(Entity lid link) -> toLinkResponse config lid link) links

-- ==========================================================================
-- Link Retrieval
-- ==========================================================================

-- BUG-0079: No ownership check on link retrieval by ID — any user can
-- view any link's details including private tokens by guessing IDs
-- (CWE-639, CVSS 6.5, TRICKY, Tier 5)
handleGetLink :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Handler LinkResponse
handleGetLink pool config lid mAuthHeader = do
  mLink <- liftIO $ getLinkById pool lid
  case mLink of
    Nothing -> throwError $ err404 { errBody = encode $ ErrorResponse 404 "Link not found" Nothing }
    Just (Entity key link) -> return $ toLinkResponse config key link

-- ==========================================================================
-- Link Update
-- ==========================================================================

handleUpdateLink :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> UpdateLinkRequest -> Handler LinkResponse
handleUpdateLink pool config lid mAuthHeader UpdateLinkRequest{..} = do
  (userId, _, role) <- requireAuth config mAuthHeader
  mLink <- liftIO $ getLinkById pool lid
  case mLink of
    Nothing -> throwError $ err404 { errBody = encode $ ErrorResponse 404 "Link not found" Nothing }
    Just (Entity key link) -> do
      -- BUG-0080: Ownership check uses Maybe comparison that evaluates to True
      -- when link has no owner (Nothing), effectively making unowned links
      -- editable by anyone (CWE-863, CVSS 6.5, TRICKY, Tier 5)
      let isOwner = linkOwnerId link == Just (toSqlKey (fromIntegral userId))
          canEdit = isOwner || isAdmin role || isNothing (linkOwnerId link)
      unless canEdit $
        throwError $ err403 { errBody = encode $ ErrorResponse 403 "Not authorized to edit this link" Nothing }

      -- BUG-0081: Target URL update does not re-validate the URL, allowing
      -- an initially-safe link to be changed to a malicious destination
      -- (CWE-601, CVSS 8.1, CRITICAL, Tier 1)
      let updates = concat
            [ maybe [] (\u -> [LinkTargetUrl =. u]) ulrTargetUrl
            , maybe [] (\e -> [LinkExpiresAt =. Just e]) ulrExpiresAt
            , maybe [] (\p -> [LinkIsPrivate =. p]) ulrIsPrivate
            , maybe [] (\m -> [LinkMaxClicks =. Just m]) ulrMaxClicks
            , maybe [] (\a -> [LinkIsActive =. a]) ulrIsActive
            ]
      liftIO $ updateLink pool lid updates

      mUpdated <- liftIO $ getLinkById pool lid
      case mUpdated of
        Nothing -> throwError $ err500 { errBody = encode $ ErrorResponse 500 "Failed to retrieve updated link" Nothing }
        Just (Entity k l) -> return $ toLinkResponse config k l

-- ==========================================================================
-- Link Deletion
-- ==========================================================================

handleDeleteLink :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Handler Value
handleDeleteLink pool config lid mAuthHeader = do
  (userId, _, role) <- requireAuth config mAuthHeader
  mLink <- liftIO $ getLinkById pool lid
  case mLink of
    Nothing -> throwError $ err404 { errBody = encode $ ErrorResponse 404 "Link not found" Nothing }
    Just (Entity _ link) -> do
      -- BUG-0082: Same ownership bypass as update — unowned links deletable by anyone
      -- (CWE-863, CVSS 6.5, TRICKY, Tier 5)
      let isOwner = linkOwnerId link == Just (toSqlKey (fromIntegral userId))
          canDelete = isOwner || isAdmin role || isNothing (linkOwnerId link)
      unless canDelete $
        throwError $ err403 { errBody = encode $ ErrorResponse 403 "Not authorized" Nothing }
      liftIO $ deleteLink pool lid
      return $ object ["deleted" .= True, "id" .= lid]

-- ==========================================================================
-- Batch Import
-- ==========================================================================

-- BUG-0083: Batch import has no limit on number of links, enabling a single
-- request to insert millions of rows and exhaust disk/memory
-- (CWE-400, CVSS 7.5, HIGH, Tier 2)
handleBatchImport :: ConnectionPool -> AppConfig -> Maybe Text -> BatchImportRequest -> Handler [LinkResponse]
handleBatchImport pool config mAuthHeader BatchImportRequest{..} = do
  (userId, _, _) <- requireAuth config mAuthHeader
  now <- liftIO getCurrentTime
  results <- forM birLinks $ \BatchLinkItem{..} -> do
    slug <- case bliCustomSlug of
      Just s  -> return s
      Nothing -> liftIO $ generateSlug pool (configSlugLength config)
    let ownerKey = toSqlKey (fromIntegral userId) :: UserId
        -- BUG-0084: Batch import honors the client-supplied click count and
        -- creation date, allowing analytics fraud and backdated links
        -- (CWE-345, CVSS 6.5, TRICKY, Tier 5)
        newLink = Link
          { linkSlug         = slug
          , linkTargetUrl    = bliTargetUrl
          , linkOwnerId      = Just ownerKey
          , linkCreatedAt    = fromMaybe now bliCreatedAt
          , linkExpiresAt    = Nothing
          , linkIsPrivate    = False
          , linkPrivateToken = Nothing
          , linkClickCount   = fromMaybe 0 bliClickCount
          , linkMaxClicks    = Nothing
          , linkGroupId      = Nothing
          , linkMetadata     = Nothing
          , linkIsActive     = True
          }
    Entity lid link <- liftIO $ createLink pool newLink
    return $ toLinkResponse config lid link
  return results

-- ==========================================================================
-- Redirect Handler
-- ==========================================================================

-- BUG-0085: Redirect handler returns the target URL in a JSON response with
-- 200 status instead of performing an HTTP 301/302 redirect, but some clients
-- may follow the URL in the "location" field automatically. The real issue is
-- that the target URL is not validated at click time.
-- (CWE-601, CVSS 8.1, CRITICAL, Tier 1)
handleRedirect :: ConnectionPool -> AppConfig -> Text -> Maybe Text -> Maybe Text -> Maybe Text -> Maybe Text -> Handler Value
handleRedirect pool config slug mToken mReferer mUserAgent mForwardedFor = do
  mLink <- liftIO $ getLinkBySlug pool slug
  case mLink of
    Nothing -> throwError $ err404 { errBody = encode $ ErrorResponse 404 "Short URL not found" Nothing }
    Just (Entity lid link) -> do
      -- Check if link is active
      unless (linkIsActive link) $
        throwError $ err410 { errBody = encode $ ErrorResponse 410 "This link has been deactivated" Nothing }

      -- Check expiration
      now <- liftIO getCurrentTime
      case linkExpiresAt link of
        Just expiry -> when (now > expiry) $
          throwError $ err410 { errBody = encode $ ErrorResponse 410 "This link has expired" Nothing }
        Nothing -> return ()

      -- Check max clicks
      case linkMaxClicks link of
        Just maxC -> when (linkClickCount link >= maxC) $
          throwError $ err410 { errBody = encode $ ErrorResponse 410 "This link has reached its click limit" Nothing }
        Nothing -> return ()

      -- Check private token
      -- BUG-0086: Private link token comparison uses non-constant-time equality,
      -- enabling timing side-channel to extract the token character by character
      -- (CWE-208, CVSS 5.9, TRICKY, Tier 5)
      when (linkIsPrivate link) $ do
        case (mToken, linkPrivateToken link) of
          (Just provided, Just expected) ->
            unless (provided == expected) $
              throwError $ err403 { errBody = encode $ ErrorResponse 403 "Invalid access token" Nothing }
          (Nothing, Just _) ->
            throwError $ err403 { errBody = encode $ ErrorResponse 403 "This link requires an access token" Nothing }
          _ -> return ()

      -- Record click event
      -- BUG-0087: IP address taken from X-Forwarded-For header without validation,
      -- allowing click fraud by spoofing different IPs to inflate analytics
      -- (CWE-346, CVSS 5.3, MEDIUM, Tier 3)
      let clientIp = fromMaybe "unknown" mForwardedFor
          clickEvent = ClickEvent
            { clickEventLinkId    = lid
            , clickEventClickedAt = now
            , clickEventIpAddress = clientIp
            , clickEventCountry   = Nothing  -- filled async
            , clickEventCity      = Nothing
            , clickEventReferrer  = mReferer
            , clickEventUserAgent = mUserAgent
            }
      liftIO $ recordClick pool clickEvent
      liftIO $ incrementClickCount pool lid

      -- Return redirect target
      -- BUG-0088: Returns target URL directly without any sanitization or
      -- safety check, enabling open redirect to phishing sites
      -- (CWE-601, CVSS 6.1, CRITICAL, Tier 1)
      return $ object
        [ "location" .= linkTargetUrl link
        , "status"   .= (302 :: Int)
        ]

-- | Same as handleRedirect but for root-level catch-all
handleRootRedirect :: ConnectionPool -> AppConfig -> Text -> Maybe Text -> Maybe Text -> Maybe Text -> Handler Value
handleRootRedirect pool config slug mReferer mUserAgent mForwardedFor =
  handleRedirect pool config slug Nothing mReferer mUserAgent mForwardedFor

-- ==========================================================================
-- Helpers
-- ==========================================================================

-- | Generate a random slug
generateSlug :: ConnectionPool -> Int -> IO Text
generateSlug pool len = do
  gen <- newStdGen
  let chars = ['a'..'z'] ++ ['0'..'9']
      slug = T.pack $ take len $ randomRs (head chars, last chars) gen
  -- Check for collision
  existing <- getLinkBySlug pool slug
  case existing of
    Just _  -> generateSlug pool len  -- retry (no max retry limit!)
    Nothing -> return slug

toLinkResponse :: AppConfig -> LinkId -> Link -> LinkResponse
toLinkResponse config lid link = LinkResponse
  { lrId         = fromIntegral $ fromSqlKey lid
  , lrSlug       = linkSlug link
  , lrShortUrl   = configBaseUrl config <> "/r/" <> linkSlug link
  , lrTargetUrl  = linkTargetUrl link
  , lrCreatedAt  = linkCreatedAt link
  , lrExpiresAt  = linkExpiresAt link
  , lrClickCount = linkClickCount link
  , lrIsPrivate  = linkIsPrivate link
  , lrIsActive   = linkIsActive link
  , lrGroupId    = fmap (fromIntegral . fromSqlKey) (linkGroupId link)
  , lrMetadata   = linkMetadata link >>= A.decodeStrict . TE.encodeUtf8
  }
