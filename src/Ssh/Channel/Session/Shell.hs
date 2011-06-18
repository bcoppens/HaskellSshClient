{-# LANGUAGE OverloadedStrings #-}

-- | Handles everything related to a remote shell. Needs to be done asynchronously because we have to wait for both local actions (keypresses) and remote actions
module Ssh.Channel.Session.Shell (
      requestShell
) where

import Data.Binary.Get
import Data.Binary.Put

import Control.Concurrent
import Data.Maybe

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B
import qualified Data.Map as Map

import Ssh.Packet
import Ssh.Channel
import Ssh.String
import Ssh.Transport
import Ssh.NetworkIO
import Ssh.Debug

-- | Request a remote shell on the channel.
--   The MVar will contain the global 'Channels' data for this channel. Whenever *anyone* (either this code, or the caller of 'requestShell') wants to communicate
--   with the server, the MVar should be used! This is so we can update the 'ChannelInfo's window size etc. safely after sending packets,
--   and to send data in a serialized way.
requestShell :: MVar (GlobalChannelInfo, SshTransportInfo) -> Channel ChannelInfo
requestShell minfo = do
    -- Request a shell on this channel
    nr <- getLocalChannelNr
    let request = ChannelRequest nr "shell" False ""
    MS.lift $ sPutPacket request

    -- Update the channel info
    info <- setChannelHandler $ handleShellRequest minfo

    MS.liftIO $ forkIO $ shellReadClientLoop nr minfo

    return info

shellReadClientLoop :: Int -> MVar (GlobalChannelInfo, SshTransportInfo) -> IO ()
shellReadClientLoop channelId channelsLock = do
    (globalInfo, transport) <- MS.liftIO $ takeMVar channelsLock

    let channelInfo = fromJust $ Map.lookup channelId (usedChannels globalInfo)

    -- globalinfo'!
    transport' <- MS.execStateT (MS.execStateT (queueDataOverChannel "echo 'hoi'" channelInfo) globalInfo) transport

    putMVar channelsLock (globalInfo, transport')

-- | Handle a shell request
handleShellRequest :: MVar (GlobalChannelInfo, SshTransportInfo) -> SshString -> Channel ChannelInfo
handleShellRequest channelsLock payload = do
    printDebugLifted logDebug "This is the result of a shell request:"
    let raw = B.unpack payload
    MS.liftIO $ putStr $ map (toEnum . fromEnum) raw
    MS.get >>= return

