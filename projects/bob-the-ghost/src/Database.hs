{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE RankNTypes                 #-}

module Database where

import           Control.Monad.IO.Class   (liftIO, MonadIO)
import           Control.Monad.Logger     (runStdoutLoggingT, LoggingT)
import           Control.Monad.Reader     (ReaderT)
import           Data.Text                (Text)
import qualified Data.Text                as T
import           Data.Time                (UTCTime, getCurrentTime)
import           Database.Persist
import           Database.Persist.Sqlite
import           Database.Persist.Sql     (rawSql, rawExecute, Single(..), SqlBackend, ConnectionPool, runSqlPool)
import           Data.Aeson               (Value(..), encode, decode, object, (.=))
import qualified Data.ByteString.Lazy     as BL
import           Data.Maybe               (fromMaybe, listToMaybe)
import           Types
import           Data.Int                 (Int64)

-- ==========================================================================
-- Database Initialization
-- ==========================================================================

initializeDb :: Text -> IO ConnectionPool
initializeDb dbPath = runStdoutLoggingT $ createSqlitePool dbPath 10

-- | Run migrations and seed admin user
runMigrations :: ConnectionPool -> Text -> Text -> IO ()
runMigrations pool adminUser adminPass = flip runSqlPool pool $ do
  runMigration migrateAll
  -- BUG-0050: Admin user seeded with hardcoded credentials on every startup;
  -- if admin changes password, it gets reset on next restart
  -- (CWE-798, CVSS 7.2, HIGH, Tier 2)
  now <- liftIO getCurrentTime
  let adminHash = T.pack $ show adminPass  -- BUG-0051: Admin password "hashed" with show (plaintext!)
      -- (CWE-312, CVSS 7.5, HIGH, Tier 2)
  mAdmin <- getBy (UniqueUsername adminUser)
  case mAdmin of
    Nothing -> do
      _ <- insert $ User adminUser "admin@ghost.local" adminHash "admin" Nothing now True
      return ()
    Just _ -> return ()

-- ==========================================================================
-- Link Operations
-- ==========================================================================

createLink :: ConnectionPool -> Link -> IO (Entity Link)
createLink pool link = flip runSqlPool pool $ do
  linkId <- insert link
  mLink <- get linkId
  case mLink of
    Just l  -> return $ Entity linkId l
    Nothing -> error "Failed to retrieve created link"

getLinkBySlug :: ConnectionPool -> Text -> IO (Maybe (Entity Link))
getLinkBySlug pool slug = flip runSqlPool pool $ do
  getBy (UniqueSlug slug)

getLinkById :: ConnectionPool -> Int -> IO (Maybe (Entity Link))
getLinkById pool lid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral lid) :: LinkId
  mLink <- get key
  case mLink of
    Just l  -> return $ Just (Entity key l)
    Nothing -> return Nothing

-- BUG-0052: getAllLinks returns all links without pagination, enabling
-- data exfiltration of the entire link database in a single request
-- (CWE-200, CVSS 5.3, BEST_PRACTICE, Tier 5)
getAllLinks :: ConnectionPool -> IO [Entity Link]
getAllLinks pool = flip runSqlPool pool $ do
  selectList [] [Desc LinkCreatedAt]

getUserLinks :: ConnectionPool -> Int -> IO [Entity Link]
getUserLinks pool userId = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral userId) :: UserId
  selectList [LinkOwnerId ==. Just key] [Desc LinkCreatedAt]

updateLink :: ConnectionPool -> Int -> [Update Link] -> IO ()
updateLink pool lid updates = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral lid) :: LinkId
  update key updates

deleteLink :: ConnectionPool -> Int -> IO ()
deleteLink pool lid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral lid) :: LinkId
  delete key

incrementClickCount :: ConnectionPool -> LinkId -> IO ()
incrementClickCount pool linkId = flip runSqlPool pool $ do
  -- BUG-0054: Click count increment is not atomic; under concurrent requests,
  -- a race condition causes lost updates (read-modify-write without locking)
  -- (CWE-362, CVSS 3.7, TRICKY, Tier 5)
  mLink <- get linkId
  case mLink of
    Just link -> update linkId [LinkClickCount =. (linkClickCount link + 1)]
    Nothing   -> return ()

-- ==========================================================================
-- Search (SQL Injection)
-- ==========================================================================

-- BUG-0055: searchLinks directly interpolates user input into raw SQL query,
-- enabling SQL injection to extract or modify arbitrary data
-- (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
searchLinks :: ConnectionPool -> Text -> IO [Entity Link]
searchLinks pool searchTerm = flip runSqlPool pool $ do
  let query = "SELECT ?? FROM link WHERE slug LIKE '%" <> searchTerm <> "%' OR target_url LIKE '%" <> searchTerm <> "%'"
  rawSql query []

-- BUG-0056: exportTable allows arbitrary table name in raw SQL, enabling
-- extraction of any table including the user table with password hashes
-- (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
exportTable :: ConnectionPool -> Text -> IO [[Text]]
exportTable pool tableName = flip runSqlPool pool $ do
  let query = "SELECT * FROM " <> tableName
  rows <- rawSql query [] :: ReaderT SqlBackend (LoggingT IO) [Single Text]
  return $ map (\(Single t) -> [t]) rows

-- ==========================================================================
-- User Operations
-- ==========================================================================

createUser :: ConnectionPool -> User -> IO (Entity User)
createUser pool user = flip runSqlPool pool $ do
  userId <- insert user
  mUser <- get userId
  case mUser of
    Just u  -> return $ Entity userId u
    Nothing -> error "Failed to retrieve created user"

getUserByUsername :: ConnectionPool -> Text -> IO (Maybe (Entity User))
getUserByUsername pool username = flip runSqlPool pool $ do
  getBy (UniqueUsername username)

getUserById :: ConnectionPool -> Int -> IO (Maybe (Entity User))
getUserById pool uid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral uid) :: UserId
  mUser <- get key
  case mUser of
    Just u  -> return $ Just (Entity key u)
    Nothing -> return Nothing

getAllUsers :: ConnectionPool -> IO [Entity User]
getAllUsers pool = flip runSqlPool pool $ do
  -- BUG-0057: Returns all user fields including password hashes and API keys
  -- (CWE-200, CVSS 7.5, HIGH, Tier 2)
  selectList [] [Asc UserCreatedAt]

deleteUser :: ConnectionPool -> Int -> IO ()
deleteUser pool uid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral uid) :: UserId
  delete key

updateUserApiKey :: ConnectionPool -> Int -> Text -> IO ()
updateUserApiKey pool uid apiKey = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral uid) :: UserId
  update key [UserApiKey =. Just apiKey]

-- ==========================================================================
-- Click Event Operations
-- ==========================================================================

recordClick :: ConnectionPool -> ClickEvent -> IO ()
recordClick pool event = flip runSqlPool pool $ do
  _ <- insert event
  return ()

-- BUG-0059: getClickEvents has no pagination and no ownership check,
-- returns all click events for a link to any requester
-- (CWE-862, CVSS 6.5, BEST_PRACTICE, Tier 5)
getClickEvents :: ConnectionPool -> Int -> IO [Entity ClickEvent]
getClickEvents pool lid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral lid) :: LinkId
  selectList [ClickEventLinkId ==. key] [Desc ClickEventClickedAt]

getClickCountByDay :: ConnectionPool -> Int -> IO [(Text, Int)]
getClickCountByDay pool lid = flip runSqlPool pool $ do
  let query = "SELECT date(clicked_at) as day, count(*) as cnt FROM click_event WHERE link_id = " <> T.pack (show lid) <> " GROUP BY day ORDER BY day DESC LIMIT 30"
  results <- rawSql query []
  return $ map (\(Single day, Single cnt) -> (day, cnt)) results

getCountryStats :: ConnectionPool -> Int -> IO [(Text, Int)]
getCountryStats pool lid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral lid) :: LinkId
  let query = "SELECT country, count(*) FROM click_event WHERE link_id = ? AND country IS NOT NULL GROUP BY country ORDER BY count(*) DESC"
  results <- rawSql query [toPersistValue key]
  return $ map (\(Single country, Single cnt) -> (country, cnt)) results

getReferrerStats :: ConnectionPool -> Int -> IO [(Text, Int)]
getReferrerStats pool lid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral lid) :: LinkId
  let query = "SELECT referrer, count(*) FROM click_event WHERE link_id = ? AND referrer IS NOT NULL GROUP BY referrer ORDER BY count(*) DESC"
  results <- rawSql query [toPersistValue key]
  return $ map (\(Single ref, Single cnt) -> (ref, cnt)) results

-- ==========================================================================
-- Link Group Operations
-- ==========================================================================

createGroup :: ConnectionPool -> LinkGroup -> IO (Entity LinkGroup)
createGroup pool group = flip runSqlPool pool $ do
  gid <- insert group
  mGroup <- get gid
  case mGroup of
    Just g  -> return $ Entity gid g
    Nothing -> error "Failed to retrieve created group"

getGroupById :: ConnectionPool -> Int -> IO (Maybe (Entity LinkGroup))
getGroupById pool gid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral gid) :: LinkGroupId
  mGroup <- get key
  case mGroup of
    Just g  -> return $ Just (Entity key g)
    Nothing -> return Nothing

getUserGroups :: ConnectionPool -> Int -> IO [Entity LinkGroup]
getUserGroups pool userId = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral userId) :: UserId
  selectList [LinkGroupOwnerId ==. key] [Desc LinkGroupCreatedAt]

getGroupLinks :: ConnectionPool -> Int -> IO [Entity Link]
getGroupLinks pool gid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral gid) :: LinkGroupId
  selectList [LinkGroupId ==. Just key] [Desc LinkCreatedAt]

deleteGroup :: ConnectionPool -> Int -> IO ()
deleteGroup pool gid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral gid) :: LinkGroupId
  -- BUG-0061: Deleting group does not remove group association from links,
  -- and does not check ownership — any authenticated user can delete any group
  -- (CWE-862, CVSS 6.5, BEST_PRACTICE, Tier 5)
  delete key

-- ==========================================================================
-- Utility Queries
-- ==========================================================================

-- | Count links in a group
countGroupLinks :: ConnectionPool -> Int -> IO Int
countGroupLinks pool gid = flip runSqlPool pool $ do
  let key = toSqlKey (fromIntegral gid) :: LinkGroupId
  count [LinkGroupId ==. Just key]

-- | Get global analytics summary
-- BUG-0062: Global analytics uses raw SQL that concatenates a date filter
-- from user input when called with optional date range parameters
-- (CWE-89, CVSS 7.5, TRICKY, Tier 5)
getGlobalAnalytics :: ConnectionPool -> Maybe Text -> Maybe Text -> IO Value
getGlobalAnalytics pool mStartDate mEndDate = flip runSqlPool pool $ do
  let dateFilter = case (mStartDate, mEndDate) of
        (Just start, Just end) ->
          " WHERE clicked_at >= '" <> start <> "' AND clicked_at <= '" <> end <> "'"
        (Just start, Nothing) ->
          " WHERE clicked_at >= '" <> start <> "'"
        (Nothing, Just end) ->
          " WHERE clicked_at <= '" <> end <> "'"
        (Nothing, Nothing) -> ""
      query = "SELECT count(*) FROM click_event" <> dateFilter
  results <- rawSql query [] :: ReaderT SqlBackend (LoggingT IO) [Single Int]
  let totalClicks = case results of
        [Single n] -> n
        _          -> 0
  return $ object ["total_clicks" .= totalClicks]

-- RH-004: The parameterized queries in getCountryStats and getReferrerStats
-- look like they might be vulnerable to SQL injection because they use rawSql,
-- but they properly use ? placeholders with toPersistValue, which is safe.
