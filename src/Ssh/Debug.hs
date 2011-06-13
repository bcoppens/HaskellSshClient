{-# LANGUAGE CPP #-}

module Ssh.Debug (
      debugRawStringData
    , logTraceMessage
    , logTraceMessageShow
    , logTraceMessageAndShow
    , printDebug
    , printDebugLifted
    , LogLevel(..)
) where

import Numeric
import Data.Char
import Data.List
import Data.List.Split
import Debug.Trace

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B

type SshString = B.ByteString

data LogLevel =
      LogDebug
    | LogWarning
    deriving Show

#ifdef DEBUG

debugLevel = LogDebug

printDebug = putStrLn
printDebugLifted s = MS.liftIO $ putStrLn s

#else

debugLevel = LogWarning

printDebug :: String -> IO ()
printDebug _ = return ()

printDebugLifted s = MS.liftIO $ return ()

#endif

-- logLevelRequired, currentLogLevel
printLogMessage :: LogLevel -> LogLevel -> String -> b -> b
printLogMessage _          LogDebug   a b = trace a b
printLogMessage LogWarning LogWarning a b = trace a b
printLogMessage _          _          _ b = b

logTraceMessage' :: LogLevel -> String -> a -> a
logTraceMessage' l s a = printLogMessage l debugLevel s a

logTraceMessageShow :: (Show a) => LogLevel -> a -> b -> b
logTraceMessageShow ll a b = logTraceMessage' ll (show a) b

logTraceMessage :: (Show a) => LogLevel -> String -> a -> a
logTraceMessage ll s a = logTraceMessage' ll s a

logTraceMessageAndShow l a b = logTraceMessageAndShow l (a ++ show b) b

convertToHexString []     = []
convertToHexString (c:cs) | c < 16    = "0" ++ (showIntAtBase 16 intToDigit c "") ++ convertToHexString cs
                          | otherwise = (showIntAtBase 16 intToDigit c "") ++ convertToHexString cs

-- | Convert a string to a format similar to OpenSSH's dumping of buffers
debugRawStringData s = concat . concat . map ((++ ["\n"]) . intersperse " ") $ splitEvery 8 $ splitEvery 4 $ convertToHexString $ B.unpack s
