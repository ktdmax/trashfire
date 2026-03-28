{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE RecordWildCards            #-}

module Types where

import           Data.Aeson
import           Data.Aeson.Types         (Parser)
import           Data.Text                (Text)
import qualified Data.Text                as T
import           Data.Time                (UTCTime)
import           Database.Persist.TH
import           GHC.Generics             (Generic)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as BL
import           Data.Maybe               (fromMaybe)
import qualified Data.HashMap.Strict      as HM
import           Data.IORef               (IORef)
import qualified Data.Map.Strict          as Map

-- ==========================================================================
-- Database Models (Persistent)
-- ==========================================================================

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
  User
    username        Text
    email           Text
    passwordHash    Text
    role            Text default='user'
    apiKey          Text Maybe
    createdAt       UTCTime
    isActive        Bool default=True
    UniqueUsername   username
    UniqueEmail     email
    deriving Show Generic

  Link
    slug            Text
    targetUrl       Text
    ownerId         UserId Maybe
    createdAt       UTCTime
    expiresAt       UTCTime Maybe
    isPrivate       Bool default=False
    privateToken    Text Maybe
    clickCount      Int default=0
    maxClicks       Int Maybe
    groupId         LinkGroupId Maybe
    metadata        Text Maybe
    isActive        Bool default=True
    UniqueSlug      slug
    deriving Show Generic

  LinkGroup
    name            Text
    ownerId         UserId
    description     Text Maybe
    createdAt       UTCTime
    isPublic        Bool default=False
    deriving Show Generic

  ClickEvent
    linkId          LinkId
    clickedAt       UTCTime
    ipAddress       Text
    country         Text Maybe
    city            Text Maybe
    referrer        Text Maybe
    userAgent       Text Maybe
    deriving Show Generic
|]

-- ==========================================================================
-- API Request/Response Types
-- ==========================================================================

data AppConfig = AppConfig
  { configDbPath       :: Text
  , configJwtSecret    :: Text
  , configBaseUrl      :: Text
  , configSlugLength   :: Int
  , configPort         :: Int
  , configAdminUser    :: Text
  , configAdminPass    :: Text
  , configGeoIpUrl     :: Text
  , configMaxQrSize    :: Int
  } deriving (Show, Generic)

-- | Global application state
data AppState = AppState
  { stateConfig    :: AppConfig
  , stateSessions  :: IORef (Map.Map Text SessionData)
  }

data SessionData = SessionData
  { sessionUserId  :: Int
  , sessionRole    :: Text
  , sessionExpiry  :: UTCTime
  } deriving (Show, Generic)

-- BUG-0020: CreateLinkRequest accepts arbitrary JSON in metadata field without
-- validation or size limits, enabling storage abuse and potential injection
-- (CWE-20, CVSS 6.5, MEDIUM, Tier 3)
data CreateLinkRequest = CreateLinkRequest
  { clrTargetUrl   :: Text
  , clrCustomSlug  :: Maybe Text
  , clrExpiresAt   :: Maybe UTCTime
  , clrIsPrivate   :: Bool
  , clrMaxClicks   :: Maybe Int
  , clrGroupId     :: Maybe Int
  , clrMetadata    :: Maybe Value  -- arbitrary JSON
  } deriving (Show, Generic)

instance FromJSON CreateLinkRequest where
  parseJSON = withObject "CreateLinkRequest" $ \v -> CreateLinkRequest
    <$> v .: "target_url"
    <*> v .:? "custom_slug"
    <*> v .:? "expires_at"
    <*> v .:? "is_private" .!= False
    <*> v .:? "max_clicks"
    <*> v .:? "group_id"
    <*> v .:? "metadata"

instance ToJSON CreateLinkRequest where
  toJSON CreateLinkRequest{..} = object
    [ "target_url"  .= clrTargetUrl
    , "custom_slug" .= clrCustomSlug
    , "expires_at"  .= clrExpiresAt
    , "is_private"  .= clrIsPrivate
    , "max_clicks"  .= clrMaxClicks
    , "group_id"    .= clrGroupId
    , "metadata"    .= clrMetadata
    ]

data UpdateLinkRequest = UpdateLinkRequest
  { ulrTargetUrl   :: Maybe Text
  , ulrExpiresAt   :: Maybe UTCTime
  , ulrIsPrivate   :: Maybe Bool
  , ulrMaxClicks   :: Maybe Int
  , ulrIsActive    :: Maybe Bool
  , ulrMetadata    :: Maybe Value
  } deriving (Show, Generic)

instance FromJSON UpdateLinkRequest where
  parseJSON = withObject "UpdateLinkRequest" $ \v -> UpdateLinkRequest
    <$> v .:? "target_url"
    <*> v .:? "expires_at"
    <*> v .:? "is_private"
    <*> v .:? "max_clicks"
    <*> v .:? "is_active"
    <*> v .:? "metadata"

instance ToJSON UpdateLinkRequest where
  toJSON UpdateLinkRequest{..} = object
    [ "target_url"  .= ulrTargetUrl
    , "expires_at"  .= ulrExpiresAt
    , "is_private"  .= ulrIsPrivate
    , "max_clicks"  .= ulrMaxClicks
    , "is_active"   .= ulrIsActive
    , "metadata"    .= ulrMetadata
    ]

data LoginRequest = LoginRequest
  { lrUsername :: Text
  , lrPassword :: Text
  } deriving (Show, Generic)

-- BUG-0021: FromJSON instance for LoginRequest does not limit field sizes,
-- allowing multi-GB username/password fields to cause OOM (CWE-400, CVSS 7.5, HIGH, Tier 2)
instance FromJSON LoginRequest where
  parseJSON = withObject "LoginRequest" $ \v -> LoginRequest
    <$> v .: "username"
    <*> v .: "password"

instance ToJSON LoginRequest where
  toJSON LoginRequest{..} = object
    [ "username" .= lrUsername
    , "password" .= lrPassword
    ]

data RegisterRequest = RegisterRequest
  { rrUsername :: Text
  , rrEmail    :: Text
  , rrPassword :: Text
  } deriving (Show, Generic)

instance FromJSON RegisterRequest where
  parseJSON = withObject "RegisterRequest" $ \v -> RegisterRequest
    <$> v .: "username"
    <*> v .: "email"
    <*> v .: "password"

instance ToJSON RegisterRequest where
  toJSON RegisterRequest{..} = object
    [ "username" .= rrUsername
    , "email"    .= rrEmail
    , "password" .= rrPassword
    ]

data TokenResponse = TokenResponse
  { trToken     :: Text
  , trExpiresIn :: Int
  , trUserId    :: Int
  , trRole      :: Text
  } deriving (Show, Generic)

instance ToJSON TokenResponse where
  toJSON TokenResponse{..} = object
    [ "token"      .= trToken
    , "expires_in" .= trExpiresIn
    , "user_id"    .= trUserId
    , "role"       .= trRole
    ]

data LinkResponse = LinkResponse
  { lrId          :: Int
  , lrSlug        :: Text
  , lrShortUrl    :: Text
  , lrTargetUrl   :: Text
  , lrCreatedAt   :: UTCTime
  , lrExpiresAt   :: Maybe UTCTime
  , lrClickCount  :: Int
  , lrIsPrivate   :: Bool
  , lrIsActive    :: Bool
  , lrGroupId     :: Maybe Int
  , lrMetadata    :: Maybe Value
  } deriving (Show, Generic)

instance ToJSON LinkResponse where
  toJSON LinkResponse{..} = object
    [ "id"          .= lrId
    , "slug"        .= lrSlug
    , "short_url"   .= lrShortUrl
    , "target_url"  .= lrTargetUrl
    , "created_at"  .= lrCreatedAt
    , "expires_at"  .= lrExpiresAt
    , "click_count" .= lrClickCount
    , "is_private"  .= lrIsPrivate
    , "is_active"   .= lrIsActive
    , "group_id"    .= lrGroupId
    , "metadata"    .= lrMetadata
    ]

data AnalyticsResponse = AnalyticsResponse
  { arLinkId       :: Int
  , arTotalClicks  :: Int
  , arClicksByDay  :: Value
  , arCountries    :: Value
  , arReferrers    :: Value
  , arUserAgents   :: Value
  } deriving (Show, Generic)

instance ToJSON AnalyticsResponse where
  toJSON AnalyticsResponse{..} = object
    [ "link_id"       .= arLinkId
    , "total_clicks"  .= arTotalClicks
    , "clicks_by_day" .= arClicksByDay
    , "countries"     .= arCountries
    , "referrers"     .= arReferrers
    , "user_agents"   .= arUserAgents
    ]

data GroupRequest = GroupRequest
  { grName        :: Text
  , grDescription :: Maybe Text
  , grIsPublic    :: Bool
  } deriving (Show, Generic)

instance FromJSON GroupRequest where
  parseJSON = withObject "GroupRequest" $ \v -> GroupRequest
    <$> v .: "name"
    <*> v .:? "description"
    <*> v .:? "is_public" .!= False

instance ToJSON GroupRequest where
  toJSON GroupRequest{..} = object
    [ "name"        .= grName
    , "description" .= grDescription
    , "is_public"   .= grIsPublic
    ]

data GroupResponse = GroupResponse
  { gresId          :: Int
  , gresName        :: Text
  , gresDescription :: Maybe Text
  , gresLinkCount   :: Int
  , gresIsPublic    :: Bool
  , gresCreatedAt   :: UTCTime
  } deriving (Show, Generic)

instance ToJSON GroupResponse where
  toJSON GroupResponse{..} = object
    [ "id"          .= gresId
    , "name"        .= gresName
    , "description" .= gresDescription
    , "link_count"  .= gresLinkCount
    , "is_public"   .= gresIsPublic
    , "created_at"  .= gresCreatedAt
    ]

data QRRequest = QRRequest
  { qrUrl  :: Text
  , qrSize :: Maybe Int
  } deriving (Show, Generic)

instance FromJSON QRRequest where
  parseJSON = withObject "QRRequest" $ \v -> QRRequest
    <$> v .: "url"
    <*> v .:? "size"

data ErrorResponse = ErrorResponse
  { errCode    :: Int
  , errMessage :: Text
  -- BUG-0022: Error responses include internal details field that leaks
  -- stack traces and internal state to API consumers (CWE-209, CVSS 5.3, MEDIUM, Tier 3)
  , errDetails :: Maybe Text
  } deriving (Show, Generic)

instance ToJSON ErrorResponse where
  toJSON ErrorResponse{..} = object
    [ "error_code" .= errCode
    , "message"    .= errMessage
    , "details"    .= errDetails
    ]

-- BUG-0023: BatchImportRequest allows importing links with pre-set click counts
-- and creation dates, enabling analytics manipulation (CWE-345, CVSS 6.5, HIGH, Tier 2)
data BatchImportRequest = BatchImportRequest
  { birLinks :: [BatchLinkItem]
  } deriving (Show, Generic)

instance FromJSON BatchImportRequest where
  parseJSON = withObject "BatchImportRequest" $ \v -> BatchImportRequest
    <$> v .: "links"

data BatchLinkItem = BatchLinkItem
  { bliTargetUrl   :: Text
  , bliCustomSlug  :: Maybe Text
  , bliClickCount  :: Maybe Int      -- allows pre-setting click counts
  , bliCreatedAt   :: Maybe UTCTime  -- allows backdating
  } deriving (Show, Generic)

instance FromJSON BatchLinkItem where
  parseJSON = withObject "BatchLinkItem" $ \v -> BatchLinkItem
    <$> v .: "target_url"
    <*> v .:? "custom_slug"
    <*> v .:? "click_count"
    <*> v .:? "created_at"

-- | Wrapper for admin operations — no runtime check on role
-- BUG-0024: AdminAction wraps any action but the role field is never verified
-- against the database, only against the JWT claim which can be forged with
-- the leaked secret (CWE-863, CVSS 8.8, HIGH, Tier 2)
data AdminAction a = AdminAction
  { aaUserId :: Int
  , aaRole   :: Text
  , aaAction :: a
  } deriving (Show, Generic)

-- RH-001: This looks like it might accept arbitrary types for deserialization,
-- but the Generic constraint and explicit field types make it safe. The
-- FromJSON instance is derived safely.
data SafeConfig = SafeConfig
  { scMaxLinks   :: Int
  , scMaxGroups  :: Int
  , scMaxClicks  :: Int
  } deriving (Show, Generic)

instance FromJSON SafeConfig where
  parseJSON = withObject "SafeConfig" $ \v -> SafeConfig
    <$> v .:? "max_links"  .!= 1000
    <*> v .:? "max_groups" .!= 100
    <*> v .:? "max_clicks" .!= 1000000
