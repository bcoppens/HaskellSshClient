{-# LANGUAGE TypeOperators #-}

-- | Implements the generic part of the SSH Connection Protocol (RFC 4254).
module Ssh.Channel(
      ChannelInfo(..)
    , Channel(..)
    , Channels(..)
    , ChannelHandler(..)
    , GlobalChannelInfo(..)
    , openChannel
    , initialGlobalChannelsState
) where

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)

import qualified Data.ByteString.Lazy as B
import qualified Control.Monad.State as MS
import qualified Data.Map as Map

import Data.List

import Ssh.Packet
import Ssh.Transport
import Ssh.Debug
import Ssh.String

-- | Keeps generic information about the channel, such as maximal packet size, and a handler.
--   The handler can update the channel information through the 'Channel' State
data ChannelInfo = ChannelInfo {
      channelClientId :: Int
    , channelServerId :: Int
    , sentEof :: Bool
    , channelWindowSizeLeft :: Int
    , channelMaxPacketSize :: Int
    , channelInfoHandler :: ChannelHandler
}

-- | A channel is stateful, and has to do socket IO
type Channel = MS.StateT ChannelInfo IO

-- | The handler for a certain channel type
data ChannelHandler = ChannelHandler {
      channelName :: SshString
      -- | Handles a given payload, using the 'ChannelInfo' in the 'Channel' state.
    , channelHandler :: SshString -> Channel ChannelInfo
}

-- | Information about a specific channel, so we can keep a mapping of live channels
data GlobalChannelInfo = GlobalChannelInfo {
    -- Maps active channels to their 'ChannelInfo' state
      usedChannels :: Map.Map Int ChannelInfo
    -- Keep a list of free channel IDs
    , freeChannels :: [Int]
}

type Channels = MS.StateT GlobalChannelInfo SshConnection

initialGlobalChannelsState = GlobalChannelInfo Map.empty [0 .. 2^31]

-- Open a channel on the given socket, with a channel type, a handler, and initial information to put in the packet's payload
openChannel :: Socket -> ChannelHandler -> SshString -> Channels ()
openChannel socket handler openInfo = do
    state <- MS.get

    -- Get a new local channel nr
    let name  = channelName handler
        local = head $ freeChannels state
        free  = take 1 $ freeChannels state

    -- Open the channel
    let remote = 42
        ws = 2^31
        ps = 32768
        chanInfo = ChannelInfo local remote False ws ps handler
        openRequest = ChannelOpen name local ws ps openInfo

    MS.lift $ sPutPacket socket openRequest

    let used  = Map.insert local chanInfo $ usedChannels state

    MS.put $ GlobalChannelInfo { usedChannels = used, freeChannels = free }
