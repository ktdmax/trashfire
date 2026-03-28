{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Handlers.Analytics where

import           Control.Monad            (when, unless)
import           Control.Monad.IO.Class   (liftIO)
import           Data.Aeson               (Value(..), object, (.=), encode, toJSON)
import qualified Data.Aeson               as A
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
import           Handlers.Auth            (requireAuth, optionalAuth, requireAdmin)
import           Database.Persist.Sqlite  (ConnectionPool)
import qualified Data.ByteString.Lazy     as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import           Data.Maybe               (fromMaybe, catMaybes)
import qualified Data.Map.Strict          as Map

-- ==========================================================================
-- Analytics Retrieval
-- ==========================================================================

-- BUG-0091: No ownership check on analytics — any authenticated user can
-- view detailed click analytics for any link by guessing its numeric ID
-- (CWE-639, CVSS 6.5, HIGH, Tier 2)
handleGetAnalytics :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Handler AnalyticsResponse
handleGetAnalytics pool config lid mAuthHeader = do
  (userId, _, role) <- requireAuth config mAuthHeader

  mLink <- liftIO $ getLinkById pool lid
  case mLink of
    Nothing -> throwError $ err404 { errBody = encode $ ErrorResponse 404 "Link not found" Nothing }
    Just (Entity _ link) -> do
      -- NOTE: no ownership check here — intentional IDOR
      clicksByDay <- liftIO $ getClickCountByDay pool lid
      countries   <- liftIO $ getCountryStats pool lid
      referrers   <- liftIO $ getReferrerStats pool lid
      events      <- liftIO $ getClickEvents pool lid

      let userAgents = aggregateUserAgents events
          dayData    = toJSON $ map (\(d, c) -> object ["date" .= d, "clicks" .= c]) clicksByDay
          countryData = toJSON $ map (\(co, c) -> object ["country" .= co, "clicks" .= c]) countries
          refData    = toJSON $ map (\(r, c) -> object ["referrer" .= r, "clicks" .= c]) referrers
          uaData     = toJSON $ map (\(ua, c) -> object ["user_agent" .= ua, "clicks" .= c]) userAgents

      return $ AnalyticsResponse
        { arLinkId      = lid
        , arTotalClicks = linkClickCount link
        , arClicksByDay = dayData
        , arCountries   = countryData
        , arReferrers   = refData
        , arUserAgents  = uaData
        }

-- ==========================================================================
-- Analytics Export
-- ==========================================================================

-- BUG-0093: Export endpoint generates CSV without escaping field values,
-- enabling CSV injection attacks when opened in spreadsheet applications.
-- Referrer and user agent fields can contain "=cmd|'/C calc'!A0" payloads
-- (CWE-1236, CVSS 7.0, TRICKY, Tier 5)
handleExportAnalytics :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Maybe Text -> Handler BL.ByteString
handleExportAnalytics pool config lid mAuthHeader mFormat = do
  (userId, _, _) <- requireAuth config mAuthHeader
  -- No ownership check (same IDOR as above)

  events <- liftIO $ getClickEvents pool lid

  let format = fromMaybe "csv" mFormat
  case format of
    "csv" -> do
      let header = "clicked_at,ip_address,country,city,referrer,user_agent\n"
          rows = map formatClickEventCsv events
          csv = BLC.pack header <> BL.concat rows
      return csv
    "json" -> do
      return $ A.encode $ map (toClickEventJson . entityVal) events
    other -> do
      return $ BLC.pack $ show $ map entityVal events

-- | Format a click event as CSV (no escaping!)
formatClickEventCsv :: Entity ClickEvent -> BL.ByteString
formatClickEventCsv (Entity _ ClickEvent{..}) =
  BLC.pack $ concat
    [ show clickEventClickedAt, ","
    , T.unpack clickEventIpAddress, ","
    -- BUG-0095: IP addresses stored and exported without anonymization,
    -- violating GDPR requirements for PII handling (CWE-359, CVSS 4.3, BEST_PRACTICE, Tier 5)
    , maybe "" T.unpack clickEventCountry, ","
    , maybe "" T.unpack clickEventCity, ","
    , maybe "" T.unpack clickEventReferrer, ","
    , maybe "" T.unpack clickEventUserAgent
    , "\n"
    ]

toClickEventJson :: ClickEvent -> Value
toClickEventJson ClickEvent{..} = object
  [ "clicked_at"  .= clickEventClickedAt
  , "ip_address"  .= clickEventIpAddress
  , "country"     .= clickEventCountry
  , "city"        .= clickEventCity
  , "referrer"    .= clickEventReferrer
  , "user_agent"  .= clickEventUserAgent
  ]

-- ==========================================================================
-- Global Analytics
-- ==========================================================================

-- BUG-0096: Global analytics endpoint accessible to any authenticated user,
-- not restricted to admins, leaking aggregate platform data
-- (CWE-862, CVSS 5.3, BEST_PRACTICE, Tier 5)
handleGlobalAnalytics :: ConnectionPool -> AppConfig -> Maybe Text -> Handler Value
handleGlobalAnalytics pool config mAuthHeader = do
  (userId, _, _) <- requireAuth config mAuthHeader
  -- Should check isAdmin but doesn't
  analytics <- liftIO $ getGlobalAnalytics pool Nothing Nothing
  return analytics

-- ==========================================================================
-- Group Handlers
-- ==========================================================================

handleCreateGroup :: ConnectionPool -> AppConfig -> Maybe Text -> GroupRequest -> Handler GroupResponse
handleCreateGroup pool config mAuthHeader GroupRequest{..} = do
  (userId, _, _) <- requireAuth config mAuthHeader
  now <- liftIO getCurrentTime
  let ownerKey = toSqlKey (fromIntegral userId) :: UserId
      newGroup = LinkGroup
        { linkGroupName        = grName
        , linkGroupOwnerId     = ownerKey
        , linkGroupDescription = grDescription
        , linkGroupCreatedAt   = now
        , linkGroupIsPublic    = grIsPublic
        }
  Entity gid group <- liftIO $ createGroup pool newGroup
  linkCount <- liftIO $ countGroupLinks pool (fromIntegral $ fromSqlKey gid)
  return $ toGroupResponse gid group linkCount

handleListGroups :: ConnectionPool -> AppConfig -> Maybe Text -> Handler [GroupResponse]
handleListGroups pool config mAuthHeader = do
  (userId, _, _) <- requireAuth config mAuthHeader
  groups <- liftIO $ getUserGroups pool userId
  mapM (\(Entity gid group) -> do
    linkCount <- liftIO $ countGroupLinks pool (fromIntegral $ fromSqlKey gid)
    return $ toGroupResponse gid group linkCount
    ) groups

handleGetGroup :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Handler GroupResponse
handleGetGroup pool config gid mAuthHeader = do
  (userId, _, role) <- requireAuth config mAuthHeader
  mGroup <- liftIO $ getGroupById pool gid
  case mGroup of
    Nothing -> throwError $ err404 { errBody = encode $ ErrorResponse 404 "Group not found" Nothing }
    -- BUG-0097: Group retrieval only checks if group is public, not ownership.
    -- Private groups viewable by any authenticated user via ID enumeration
    -- (CWE-639, CVSS 4.3, TRICKY, Tier 5)
    Just (Entity key group) -> do
      unless (linkGroupIsPublic group || isAdmin role) $
        return ()  -- should throwError but doesn't!
      linkCount <- liftIO $ countGroupLinks pool gid
      return $ toGroupResponse key group linkCount

handleGetGroupLinks :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Handler [LinkResponse]
handleGetGroupLinks pool config gid mAuthHeader = do
  _ <- requireAuth config mAuthHeader  -- auth required but no ownership check
  links <- liftIO $ getGroupLinks pool gid
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
      , lrMetadata   = linkMetadata link >>= A.decodeStrict . TE.encodeUtf8
      }

handleDeleteGroup :: ConnectionPool -> AppConfig -> Int -> Maybe Text -> Handler Value
handleDeleteGroup pool config gid mAuthHeader = do
  (userId, _, role) <- requireAuth config mAuthHeader
  -- BUG-0098: No ownership verification on group deletion — any authenticated
  -- user can delete any group (CWE-862, CVSS 6.5, TRICKY, Tier 5)
  liftIO $ deleteGroup pool gid
  return $ object ["deleted" .= True, "group_id" .= gid]

-- ==========================================================================
-- Helpers
-- ==========================================================================

aggregateUserAgents :: [Entity ClickEvent] -> [(Text, Int)]
aggregateUserAgents events =
  let uas = catMaybes $ map (clickEventUserAgent . entityVal) events
      counts = foldl (\m ua -> Map.insertWith (+) ua 1 m) Map.empty uas
  in Map.toDescList counts

toGroupResponse :: LinkGroupId -> LinkGroup -> Int -> GroupResponse
toGroupResponse gid group linkCount = GroupResponse
  { gresId          = fromIntegral $ fromSqlKey gid
  , gresName        = linkGroupName group
  , gresDescription = linkGroupDescription group
  , gresLinkCount   = linkCount
  , gresIsPublic    = linkGroupIsPublic group
  , gresCreatedAt   = linkGroupCreatedAt group
  }

-- RH-006: The aggregateUserAgents function uses Map.insertWith which might
-- look vulnerable to HashDoS, but Data.Map.Strict uses a balanced tree
-- (not a hash map), so it has O(log n) insert regardless of input.
