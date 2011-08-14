{-# LANGUAGE OverloadedStrings #-}

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
    , queueDataOverChannel
    , handleChannel
    , setChannelPayloadHandler
    , addChannelCloseHandler
    -- * Miscelaneous
    , initialGlobalChannelsState
    , getLocalChannelNr
) where

import qualified Data.ByteString.Lazy as B
import qualified Control.Monad.State as MS
import qualified Data.Map as Map

import Control.Monad
import Data.Maybe
import Data.List

import Ssh.Packet
import Ssh.Transport
import Ssh.Debug
import Ssh.String

-- | Keeps generic information about the channel, such as maximal packet size, and a handler.
--   The handler can update the channel information through the 'Channel' State
data ChannelInfo = ChannelInfo {
      channelLocalId :: Int
    , channelRemoteId :: Maybe Int              -- ^ Nothing if we have not yet received the OpenConfirmation with the remote ID, or Just remoteId
    , closed :: Bool
    , sentEof :: Bool
    , gotEof  :: Bool
    , channelLocalWindowSizeLeft :: Int
    , channelLocalMaxPacketSize :: Int
    , channelRemoteWindowSizeLeft :: Maybe Int  -- ^ Nothing if we have not yet received the OpenConfirmation from the remote, or Just windowSizeLeft
    , channelRemoteMaxPacketSize :: Maybe Int   -- ^ Nothing if we have not yet received the OpenConfirmation from the remote, or Just maxPacketSize
    , queuedData :: SshString                   -- ^ If we try to send data when windowsize is too small, store it here until we get WindowsizeAdjust
    , channelInfoHandler :: ChannelHandler
}

-- | A channel is stateful, and has to do socket IO over the 'SshConnection'
type Channel = MS.StateT ChannelInfo SshConnection

-- | The handler for a certain channel type
data ChannelHandler = ChannelHandler {
      channelName :: SshString
      -- | Handles a given payload, using the 'ChannelInfo' in the 'Channel' state.
    , handleChannelPayload :: SshString -> Channel ChannelInfo
      -- | When a channel gets closed, this function is called to handle some cleanup
    , handleChannelClose :: Channel ()
}

-- | Information about a specific channel, so we can keep a mapping of live channels
data GlobalChannelInfo = GlobalChannelInfo {
    -- Maps active channels (on their local ID, because the remote will send with the recipientChannel) to their 'ChannelInfo' state
      usedChannels :: Map.Map Int ChannelInfo
    -- Keep a list of free channel IDs
    , freeChannels :: [Int]
}

type Channels = MS.StateT GlobalChannelInfo SshConnection

initialGlobalChannelsState = GlobalChannelInfo Map.empty [0 .. 2^31]

-- | Set the payload handler for a channel
setChannelPayloadHandler :: (SshString -> Channel ChannelInfo) -> Channel ChannelInfo
setChannelPayloadHandler handler = do
    s <- MS.get
    let cih  = channelInfoHandler s
        cih' = cih { handleChannelPayload = handler }
        ret  = s { channelInfoHandler = cih' }
    return $ ret

-- | Add a close handler for a channel
addChannelCloseHandler :: ChannelInfo -> (Channel ()) -> ChannelInfo
addChannelCloseHandler s handler =
    let cih  = channelInfoHandler s
        cih' = cih { handleChannelClose = handler }
        ret  = s { channelInfoHandler = cih' }
    in  ret

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
    let remoteId    = Nothing
        ws          = 2^31
        ps          = 32768
        chanInfo    = ChannelInfo local remoteId False False False ws ps Nothing Nothing "" handler
        openRequest = ChannelOpen name local ws ps openInfo

    -- Request to open the channel
    MS.lift $ sPutPacket openRequest

    let used  = Map.insert local chanInfo $ usedChannels state

    MS.put $ GlobalChannelInfo { usedChannels = used, freeChannels = free }

    return chanInfo


-- TODO actually split/queue if the packetSize/windowSize indicates to split!
-- | Queue payload to be sent over the channel indicated by 'ChannelInfo'.
--   This data might be sent directly, or might be queued, or split, depending on how the size of the payload compares to the channel's
--   'channelRemoteWindowSizeLeft' and 'channelRemotePacketSize'.
queueDataOverChannel :: SshString -> ChannelInfo -> Channels ()
queueDataOverChannel payload channel = do
    let localChannel  = channelLocalId channel
        sendSize      = B.length payload -- The length of the payload we have to send

    -- See if we have to queue the data, or can send (part of it) it right away (TODO: packet size)
    let bytesToSend = do
            remote     <- channelRemoteId channel              -- If the remote has not yet sent its ChannelOpen, we have to queue the data
            windowLeft <- channelRemoteWindowSizeLeft channel  -- if the remote's windowsize is too small, queue data!
            let shouldSend =  min (toEnum windowLeft) sendSize -- We can send this many bytes
            if shouldSend <= 0
                then Nothing
                else Just shouldSend

    -- If the queue already contains data, this *must* also queue (i.e. append) it. Is ok, because we dequeue data automatically when we get a window size increase
    case bytesToSend of
        Nothing    -> queueBytes payload localChannel          -- Queue everything
        Just bytes -> do                                       -- Send part, queue the rest
            let (toSend, toQueue) = B.splitAt bytes payload
            sendDataOverChannel toSend channel localChannel
            queueBytes toQueue localChannel                    -- If this is empty, it'll just get ignored when we get a window size increase, etc.

-- | Append these bytes to the 'ChannelInfo's send queue
queueBytes :: SshString -> Int -> Channels ()
queueBytes payload localId = do
    when (not $ B.null payload) $ printDebugLifted logDebug $ "Queuing bytes: " ++ show payload

    updateInfoWith localId $ \info -> info { queuedData = queuedData info `B.append` payload }

    return ()

-- TODO: packetsize?
-- | Send (potentially previously queued) data to the remote *now* (the remote channel is assumed to be open, etc)
sendDataOverChannel :: SshString -> ChannelInfo -> Int -> Channels ()
sendDataOverChannel payload channel localId = do
    let remoteChannel = fromJust $ channelRemoteId channel
        request       = ChannelData remoteChannel payload

    -- Send the data
    MS.lift $ sPutPacket request

    -- We sent some bytes, which decreases the available window size of the remote
    updateInfoWith localId $ \info -> info { channelRemoteWindowSizeLeft = Just $ (fromJust $ channelRemoteWindowSizeLeft info) - (fromIntegral $ B.length payload) }

    return ()

-- | Get the 'ChannelInfo' with this local id, if it exists yet
getChannel :: Int -> Channels (Maybe ChannelInfo)
getChannel local = do
    state <- MS.get
    return $ Map.lookup local (usedChannels state)

-- | Looks up the local channel id, applies the update function to it, and return it. Makes handleChannel somewhat less repetitive to write
updateInfoWith :: Int -> (ChannelInfo -> ChannelInfo) -> Channels ChannelInfo
updateInfoWith nr action = do
    info <- fromJust `liftM` getChannel nr
    let newInfo = action info
    modifyUsedChannel nr newInfo
    return newInfo

-- | Handle a 'Packet' coming to us. Can dispatch the request to a 'Channel's handler, or change the window size of a 'Channel', confirm its opening, closing, etc.
handleChannel :: Packet -> Channels ChannelInfo

-- The channel was correctly opened. Update the remote information for this channel
handleChannel (ChannelOpenConfirmation recipientNr senderNr initWS maxPS payload) = do
    updateInfoWith recipientNr $ \info -> info { channelRemoteId = Just senderNr, channelRemoteWindowSizeLeft = Just initWS, channelRemoteMaxPacketSize = Just maxPS }

-- The remote says we can send some more bytes to this channel. Increase the window size, and send the sendQueue if needed
handleChannel (ChannelWindowAdjust nr toAdd) = do
    info  <- fromJust `liftM` getChannel nr

    -- Remove the payload, increase the window size
    let queue   = queuedData info
        action  = \info -> info {
              channelRemoteWindowSizeLeft = Just $ toAdd + (fromJust $ channelRemoteWindowSizeLeft info)
            , queuedData = B.empty
        }
        newInfo = action info

    -- Write new info
    modifyUsedChannel nr newInfo

    -- See if we have to try to send (part of) or queue
    if B.null queue
        then return newInfo
        else do
            printDebugLifted logDebug $ "Window size increased, requeing data"

            queueDataOverChannel queue newInfo
            fromJust `liftM` getChannel nr >>= return

-- Remote sends that his side has reached an EOF
handleChannel (ChannelEof nr) = do
    updateInfoWith nr $ \info -> info { gotEof = True }

-- Remote closed this channel, remove it from our list for later reuse once we have it removed too
handleChannel (ChannelClose nr) = do
    -- We must send back a ChannelClose, and actually close this channel
    info   <- fromJust `liftM` getChannel nr
    MS.lift $ sPutPacket $ ChannelClose $ fromJust $ channelRemoteId info

    -- Set this channel to closed locally
    closed <- updateInfoWith nr $ \info -> info { gotEof = True }

    -- Now that the channel is closed, call the close handler of this channel:
    MS.lift $ MS.runStateT (handleChannelClose (channelInfoHandler info)) info

    -- This channel is free again to be reused in our Channels state
    state  <- MS.get
    let newUsedChannels = Map.delete nr $ usedChannels state
        newFreeChannels = nr : freeChannels state
    MS.put $ GlobalChannelInfo { usedChannels = newUsedChannels, freeChannels = newFreeChannels }

    return info

-- Extended data can be stuff like standard error
handleChannel (ChannelExtendedData nr code payload) = do
    case code of
        1 -> -- SSH_EXTENDED_DATA_STDERR
            -- TODO: handle with handler?
            MS.liftIO $ putStrLn $ "Server sent back on standard error: " ++ (map (toEnum . fromEnum) $ B.unpack payload)
        _ ->
            printDebugLifted logWarning $ "Unknown channel data type: " ++ show code
    info <- fromJust `liftM` getChannel nr
    return info

-- When data comes in for one of our channels, be sure to see to which one it is, and dispatch the payload data to it to update
handleChannel (ChannelData nr payload) = do
    state <- MS.get

    -- Which channel handler?
    let info = Map.lookup nr $ usedChannels state
    case info of
        Just cInfo -> do
            -- Let the handler do its stuff, get the result, update our map with the newly returned ChannelInfo, which can contain a brand new handler
            let newChannel = handleChannelPayload (channelInfoHandler cInfo) $ payload :: Channel ChannelInfo
            (newChannelInfo, newState) <- MS.lift $ MS.runStateT newChannel cInfo
            modifyUsedChannel nr newChannelInfo
            return newState
        Nothing    -> do
            printDebugLifted logWarning $ "No handler found at lookup for channel " ++ show nr
            return $ error "No handler!"

-- TODO Handle other cases we don't care about yet
-- And these messages we don't know about. Throw to lower level protocol handling functions! TODO
handleChannel p = do
    state <- MS.get
    printDebugLifted logDebugExtended "HandleChannel: ignored packet"
    return $ error "Handle Channel: ignored packet handled"
