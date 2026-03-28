{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE TypeOperators     #-}

module Main where

import           Control.Monad            (void)
import           Control.Monad.IO.Class   (liftIO)
import           Data.Aeson               (Value(..), object, (.=))
import qualified Data.Aeson               as A
import           Data.IORef               (newIORef)
import           Data.Text                (Text)
import qualified Data.Text                as T
import qualified Data.Text.IO             as TIO
import qualified Data.Map.Strict          as Map
import           Network.Wai              (Application, Middleware)
import           Network.Wai.Handler.Warp (run, setPort, setHost, defaultSettings)
import qualified Network.Wai.Handler.Warp as Warp
import           Network.Wai.Middleware.Cors (simpleCors, cors, simpleHeaders,
                                              CorsResourcePolicy(..), simpleCorsResourcePolicy)
import           Servant
import           Api
import           Types
import           Auth
import           Database
import           Handlers.Auth
import           Handlers.Links
import           Handlers.Analytics
import           QR
import           Database.Persist.Sqlite  (ConnectionPool)
import qualified Data.ByteString.Lazy     as BL

-- ==========================================================================
-- Main Entry Point
-- ==========================================================================

main :: IO ()
main = do
  putStrLn "=== bob-the-ghost URL Shortener ==="
  putStrLn "Starting server..."

  -- Load configuration (hardcoded for now)
  let config = AppConfig
        { configDbPath     = "bob-the-ghost.db"
        , configJwtSecret  = "super-secret-jwt-key-change-me-in-production-2024"
        , configBaseUrl    = "http://localhost:8080"
        , configSlugLength = 6
        , configPort       = 8080
        , configAdminUser  = "admin"
        , configAdminPass  = "ghostly-admin-2024"
        , configGeoIpUrl   = "http://ip-api.com/json/"
        , configMaxQrSize  = 4096
        }

  -- Initialize database
  pool <- initializeDb (configDbPath config)
  runMigrations pool (configAdminUser config) (configAdminPass config)

  -- Initialize session store
  sessionsRef <- newIORef Map.empty
  let state = AppState config sessionsRef

  -- BUG-0113: Server startup prints JWT secret and admin credentials to stdout
  -- (CWE-532, CVSS 7.5, HIGH, Tier 2)
  putStrLn $ "JWT Secret: " ++ T.unpack (configJwtSecret config)
  putStrLn $ "Admin: " ++ T.unpack (configAdminUser config) ++ "/" ++ T.unpack (configAdminPass config)
  putStrLn $ "Listening on port " ++ show (configPort config)

  -- Run server
  let settings = Warp.setPort (configPort config)
               $ Warp.setHost "*"  -- binds to all interfaces
               $ Warp.defaultSettings
  -- BUG-0114: No request size limit set on Warp, allowing arbitrarily large
  -- request bodies that can exhaust server memory (CWE-400, CVSS 7.5, HIGH, Tier 2)
  Warp.runSettings settings $ corsMiddleware $ app pool config

-- ==========================================================================
-- CORS Middleware
-- ==========================================================================

-- BUG-0115: CORS middleware allows all origins with credentials, which browsers
-- will reject — but the real issue is the Access-Control-Allow-Origin header
-- is set to the request Origin, effectively reflecting any origin
-- (CWE-942, CVSS 7.5, BEST_PRACTICE, Tier 5)
corsMiddleware :: Middleware
corsMiddleware = cors $ \_ -> Just CorsResourcePolicy
  { corsOrigins        = Nothing  -- allows all origins
  , corsMethods        = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  , corsRequestHeaders = simpleHeaders ++ ["Authorization", "Content-Type"]
  , corsExposedHeaders = Nothing
  , corsMaxAge         = Just 86400
  , corsVaryOrigin     = False
  , corsRequireOrigin  = False
  , corsIgnoreFailures = True  -- silently ignores CORS failures
  }

-- ==========================================================================
-- Application
-- ==========================================================================

app :: ConnectionPool -> AppConfig -> Application
app pool config = serve ghostApi (server pool config)

server :: ConnectionPool -> AppConfig -> Server GhostAPI
server pool config =
  (    -- API v1
       (    -- Auth
                 handleLogin pool config
            :<|> handleRegister pool config
            :<|> handleRefreshToken pool config
            :<|> handleGenerateApiKey pool config
       )
       :<|> (   -- Links
                 handleCreateLink pool config
            :<|> handleListLinks pool config
            :<|> handleGetLink pool config
            :<|> handleUpdateLink pool config
            :<|> handleDeleteLink pool config
            :<|> handleBatchImport pool config
       )
       :<|> (   -- Groups
                 handleCreateGroup pool config
            :<|> handleListGroups pool config
            :<|> handleGetGroup pool config
            :<|> handleGetGroupLinks pool config
            :<|> handleDeleteGroup pool config
       )
       :<|> (   -- Analytics
                 handleGetAnalytics pool config
            :<|> handleExportAnalytics pool config
            :<|> handleGlobalAnalytics pool config
       )
       :<|> (   -- QR
                 handleGenerateQR pool config
            :<|> handleBatchQR pool config
       )
       :<|> (   -- Admin
                 handleAdminListUsers pool config
            :<|> handleAdminDeleteUser pool config
            :<|> handleAdminSearchLinks pool config
            :<|> handleAdminUpdateConfig pool config
            :<|> handleAdminExport pool config
       )
       :<|> handleRedirect pool config  -- /api/v1/r/:slug
  )
  :<|> handleHealthCheck                -- /health
  :<|> handleRootRedirect pool config   -- /:slug catch-all
