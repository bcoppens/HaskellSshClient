{-# LANGUAGE TypeOperators #-}

-- | Implements the generic part of the SSH Connection Protocol (RFC 4254).
module Ssh.Channel(
    -- * Data structures
      ChannelInfo(..)
    , Channel(..)
    , Channels(..)
    , ChannelHandler(..)
    , GlobalChannelInfo(..)
    -- * Perform actions on a 'Channel'
    , runGlobalChannelsToConnection
    , insertChannel
    -- * Request actions related to 'Channel's
    , openChannel
    , handleChannel
    -- * Miscelaneous
    , initialGlobalChannelsState
    , getLocalChannelNr
) where

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
      channelLocalId :: Int
    , channelRemoteId :: Int
    , sentEof :: Bool
    , channelWindowSizeLeft :: Int
    , channelMaxPacketSize :: Int
    , channelInfoHandler :: ChannelHandler
}

-- | A channel is stateful, and has to do socket IO over the 'SshConnection'
type Channel = MS.StateT ChannelInfo SshConnection

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


-- | Run the action of 'Channels ChannelInfo' on the initial 'GlobalChannelInfo', and at the end just return the resulting connection. Can be used for
--   an execution loop, after which the connection should be closed
runGlobalChannelsToConnection :: GlobalChannelInfo -> Channels a -> SshConnection ()
runGlobalChannelsToConnection state action = do
    MS.runStateT action state
    return ()

-- | Run the 'Channel ChannelInfo' action on the channel with the specified 'ChannelInfo', get the resulting info and update it in our 'Channels' state
insertChannel :: ChannelInfo -> Channel ChannelInfo -> Channels ()
insertChannel channel action = do
    newChannelInfo <- MS.lift $ MS.evalStateT action channel
    let channelNr = channelLocalId channel
    modifyUsedChannel channelNr newChannelInfo

-- | Get the local channel number of a Channel
getLocalChannelNr :: Channel Int
getLocalChannelNr = channelLocalId `fmap` MS.get

modifyUsedChannel :: Int -> ChannelInfo -> Channels ()
modifyUsedChannel chanNr newChannelInfo = MS.modify $ \s -> s { usedChannels = Map.insert chanNr newChannelInfo $ usedChannels s }

-- TODO: handle the open confirmation to map server ID to local ID!

-- | Open a channel on the given 'SshConnection' given in the 'Channels' state, with a channel type, a handler, and initial information to put in the packet's payload
openChannel :: ChannelHandler -> SshString -> Channels ChannelInfo
openChannel handler openInfo = do
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

    -- Request to open the channel
    MS.lift $ sPutPacket openRequest

    let used  = Map.insert local chanInfo $ usedChannels state

    MS.put $ GlobalChannelInfo { usedChannels = used, freeChannels = free }

    return chanInfo

-- | When data comes in for one of our channels, be sure to see to which one it is, and dispatch the payload data to it to update
handleChannel :: Packet -> Channels ChannelInfo
handleChannel (ChannelData nr payload) = do
    state <- MS.get

    -- Which channel handler?
    let info = Map.lookup nr $ usedChannels state
    case info of
        Just cInfo -> do
            -- Let the handler do its stuff, get the result, update our map with the newly returned ChannelInfo, which can contain a brand new handler
            let newChannel = channelHandler (channelInfoHandler cInfo) $ payload :: Channel ChannelInfo
            (newChannelInfo, newState) <- MS.lift $ MS.runStateT newChannel cInfo
            modifyUsedChannel nr newChannelInfo
            return newState
        Nothing    -> do
            printDebugLifted logWarning $ "No handler found at lookup for channel " ++ show nr
            return $ error "No handler!"

-- TODO throw to lower level protocol handling functions!
handleChannel p = do
    state <- MS.get
    printDebugLifted logDebugExtended "HandleChannel: ignored packet"
    return $ error "Handle Channel: ignored packet"
