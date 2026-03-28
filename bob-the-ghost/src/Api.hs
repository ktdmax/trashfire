{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE TypeOperators     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric     #-}

module Api where

import           Data.Text        (Text)
import           Servant
import           Types
import           Data.Aeson       (Value)
import qualified Data.ByteString.Lazy as BL

-- ==========================================================================
-- API Type Definition
-- ==========================================================================

-- | Main API type combining all sub-APIs
type GhostAPI =
       "api" :> "v1" :> (
              AuthAPI
         :<|> LinksAPI
         :<|> GroupsAPI
         :<|> AnalyticsAPI
         :<|> QRCodeAPI
         :<|> AdminAPI
         :<|> RedirectAPI
       )
  :<|> HealthAPI
  :<|> RedirectCatchAll

-- | Authentication endpoints
type AuthAPI =
       "auth" :> "login"    :> ReqBody '[JSON] LoginRequest    :> Post '[JSON] TokenResponse
  :<|> "auth" :> "register" :> ReqBody '[JSON] RegisterRequest :> Post '[JSON] TokenResponse
  :<|> "auth" :> "refresh"  :> Header "Authorization" Text     :> Post '[JSON] TokenResponse
  -- BUG-0025: Token refresh endpoint does not invalidate the old token,
  -- allowing unlimited token accumulation (CWE-613, CVSS 5.4, MEDIUM, Tier 3)
  :<|> "auth" :> "api-key"  :> Header "Authorization" Text     :> Post '[JSON] Value

-- | Link management endpoints
type LinksAPI =
       "links" :> Header "Authorization" Text
               :> ReqBody '[JSON] CreateLinkRequest
               :> Post '[JSON] LinkResponse
  :<|> "links" :> Header "Authorization" Text
               :> Get '[JSON] [LinkResponse]
  -- BUG-0026: GET /links with no auth header returns ALL links in the system
  -- instead of returning an error, leaking all URLs (CWE-862, CVSS 7.5, HIGH, Tier 2)
  :<|> "links" :> Capture "linkId" Int
               :> Header "Authorization" Text
               :> Get '[JSON] LinkResponse
  -- BUG-0027: Link lookup by integer ID allows sequential enumeration of all
  -- links regardless of ownership (CWE-639, CVSS 6.5, HIGH, Tier 2)
  :<|> "links" :> Capture "linkId" Int
               :> Header "Authorization" Text
               :> ReqBody '[JSON] UpdateLinkRequest
               :> Put '[JSON] LinkResponse
  :<|> "links" :> Capture "linkId" Int
               :> Header "Authorization" Text
               :> Delete '[JSON] Value
  :<|> "links" :> "batch"
               :> Header "Authorization" Text
               :> ReqBody '[JSON] BatchImportRequest
               :> Post '[JSON] [LinkResponse]

-- | Link group endpoints
type GroupsAPI =
       "groups" :> Header "Authorization" Text
                :> ReqBody '[JSON] GroupRequest
                :> Post '[JSON] GroupResponse
  :<|> "groups" :> Header "Authorization" Text
                :> Get '[JSON] [GroupResponse]
  :<|> "groups" :> Capture "groupId" Int
                :> Header "Authorization" Text
                :> Get '[JSON] GroupResponse
  :<|> "groups" :> Capture "groupId" Int
                :> "links"
                :> Header "Authorization" Text
                :> Get '[JSON] [LinkResponse]
  :<|> "groups" :> Capture "groupId" Int
                :> Header "Authorization" Text
                :> Delete '[JSON] Value

-- | Analytics endpoints
type AnalyticsAPI =
       "analytics" :> Capture "linkId" Int
                   :> Header "Authorization" Text
                   :> Get '[JSON] AnalyticsResponse
  -- BUG-0028: Analytics endpoint does not verify link ownership; any
  -- authenticated user can view analytics for any link by ID (CWE-639, CVSS 6.5, HIGH, Tier 2)
  :<|> "analytics" :> Capture "linkId" Int
                   :> "export"
                   :> Header "Authorization" Text
                   :> QueryParam "format" Text
                   :> Get '[OctetStream] BL.ByteString
  :<|> "analytics" :> "global"
                   :> Header "Authorization" Text
                   :> Get '[JSON] Value

-- | QR code generation
type QRCodeAPI =
       "qr" :> Capture "slug" Text
            :> QueryParam "size" Int
            :> Get '[OctetStream] BL.ByteString
  -- BUG-0029: QR endpoint is unauthenticated and has no rate limiting,
  -- allowing DoS via rapid generation of large QR codes (CWE-770, CVSS 7.5, HIGH, Tier 2)
  :<|> "qr" :> "batch"
            :> Header "Authorization" Text
            :> ReqBody '[JSON] [Text]
            :> Post '[OctetStream] BL.ByteString
  -- BUG-0030: Batch QR generation accepts unbounded list of slugs,
  -- causing memory exhaustion (CWE-400, CVSS 7.5, HIGH, Tier 2)

-- | Admin endpoints
type AdminAPI =
       "admin" :> "users"
               :> Header "Authorization" Text
               :> Get '[JSON] [Value]
  :<|> "admin" :> "users" :> Capture "userId" Int
               :> Header "Authorization" Text
               :> Delete '[JSON] Value
  :<|> "admin" :> "links"
               :> Header "Authorization" Text
               :> QueryParam "search" Text
               :> Get '[JSON] [LinkResponse]
  -- BUG-0031: Admin search parameter is interpolated into raw SQL query
  -- without parameterization (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  :<|> "admin" :> "config"
               :> Header "Authorization" Text
               :> ReqBody '[JSON] Value
               :> Put '[JSON] Value
  -- BUG-0032: Admin config endpoint accepts arbitrary JSON that gets written
  -- to the config file, allowing runtime reconfiguration of security settings
  -- (CWE-15, CVSS 8.6, HIGH, Tier 2)
  :<|> "admin" :> "export"
               :> Header "Authorization" Text
               :> QueryParam "table" Text
               :> Get '[OctetStream] BL.ByteString
  -- BUG-0033: Export endpoint table parameter used in raw SQL, enabling
  -- SQL injection to dump arbitrary database tables (CWE-89, CVSS 9.8, CRITICAL, Tier 1)

-- | Redirect endpoint (the core short URL feature)
type RedirectAPI =
       "r" :> Capture "slug" Text
           :> QueryParam "token" Text
           :> Header "Referer" Text
           :> Header "User-Agent" Text
           :> Header "X-Forwarded-For" Text
           :> Get '[JSON] Value

-- | Health check
type HealthAPI =
       "health" :> Get '[JSON] Value

-- | Catch-all redirect at root level
-- BUG-0034: Root-level catch-all redirect means any path not matching an API
-- route is treated as a slug lookup, potentially leaking internal route info
-- through error messages (CWE-209, CVSS 3.7, LOW, Tier 4)
type RedirectCatchAll =
       Capture "slug" Text
       :> Header "Referer" Text
       :> Header "User-Agent" Text
       :> Header "X-Forwarded-For" Text
       :> Get '[JSON] Value

-- RH-002: The API uses Servant's type-level routing which provides compile-time
-- route safety. This looks like it might allow route confusion attacks, but
-- Servant's type system prevents overlapping route ambiguity at compile time.

ghostApi :: Proxy GhostAPI
ghostApi = Proxy
