{-# LANGUAGE CPP #-}

-- | Debug facilities. Are only enabled with -DDEBUG
module Ssh.Debug (
      debugRawStringData
    , logTraceMessage
    , logTraceMessageShow
    , logTraceMessageAndShow
    , printDebug
    , printDebugLifted
    , LogLevel(..)
    , logLowLevelDebug
    , logDebugExtended
    , logDebug
    , logWarning
) where

import Numeric
import Data.Char
import Data.List
import Data.List.Split
import Debug.Trace
import Ssh.String

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B


type LogLevel = Int

logLowLevelDebug, logDebug, logDebugExtended, logWarning :: LogLevel

logLowLevelDebug = 200   -- ^ For Very Low Level Debug Output
logDebugExtended = 150   -- ^ Somewhat extended debug output (i.e. also print out received/sent packets)
logDebug         = 100   -- ^ Regular Debug Output
logWarning       = 10    -- ^ Warnings

-- | The debug level that is currently in use. Log values <= 'debugLevel' will be logged. Use -DDEBUGLEVEL to set your own
debugLevel :: Int

-- | IO action that takes a log level and a log message. The message will get printed if the log level <= 'debugLevel'
printDebug :: LogLevel -> String -> IO ()

#ifdef DEBUG

#ifndef DEBUGLEVEL

debugLevel = logDebug

#else

debugLevel = DEBUGLEVEL

#endif


printDebug ll | ll <= debugLevel = putStrLn
              | otherwise        = \_ -> return ()

#else

debugLevel = logWarning

printDebug _ _ = return ()

#endif

-- | Variant of 'printDebug' that has been lifted with 'MS.liftIO'
printDebugLifted ll s = MS.liftIO $ printDebug ll s


-- logLevelRequired, currentLogLevel
printLogMessage :: LogLevel -> String -> b -> b
printLogMessage ll a b | ll <= debugLevel = trace a b
                       | otherwise        = b

logTraceMessage' :: LogLevel -> String -> a -> a
logTraceMessage' = printLogMessage

-- | Similar to 'Debug.Trace.Show'
logTraceMessageShow :: (Show a) => LogLevel -> a -> b -> b
logTraceMessageShow ll a b = logTraceMessage' ll (show a) b

-- | Similar to 'Debug.Trace.Show'
logTraceMessage :: (Show a) => LogLevel -> String -> a -> a
logTraceMessage ll s a = logTraceMessage' ll s a

-- | Similar to 'Debug.Trace.Show'
logTraceMessageAndShow l a b = logTraceMessageAndShow l (a ++ show b) b

convertToHexString []     = []
convertToHexString (c:cs) | c < 16    = "0" ++ (showIntAtBase 16 intToDigit c "") ++ convertToHexString cs
                          | otherwise = (showIntAtBase 16 intToDigit c "") ++ convertToHexString cs

-- | Convert a string to a format similar to OpenSSH's dumping of buffers
debugRawStringData s = concat . concat . map ((++ ["\n"]) . intersperse " ") $ splitEvery 8 $ splitEvery 4 $ convertToHexString $ B.unpack s
