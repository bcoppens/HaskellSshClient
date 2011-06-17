{-# LANGUAGE OverloadedStrings #-}

-- | Support for interactive sessions, remote executions, etc. as per SSH Connection Protocol (RFC 4251) Section 6.
module Ssh.Channel.Session (
      sessionHandler
    , requestExec
)
where

import Data.Binary.Get
import Data.Binary.Put

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B

import Ssh.Packet
import Ssh.Channel
import Ssh.String
import Ssh.Transport
import Ssh.NetworkIO
import Ssh.Debug

-- | This is the default handler for a session
sessionHandler = ChannelHandler "session" handleDefaultSession

-- | Different kinds of sessions are supported
data SessionType =
    -- | Execute a remote command
      ExecuteCommand

-- | Different kinds of request can be sent to the server
data SessionRequest =
    -- | Execute a remote command with the given string
    ExecRequest {
        execCommand :: SshString
      }

-- | 'Put' for sending a request to the server with its associated payload
putSessionData :: SessionRequest -> Put
putSessionData (ExecRequest e) = do
    putString e

-- TODO: verify that this is an open "ssh-connection" channel?

-- | Given the socket, run the specified command remotely on this 'Channel'
requestExec :: Socket -> SshString -> Channel ChannelInfo
requestExec socket cmd = do
    -- Request the "exec" command on this channel
    nr <- getLocalChannelNr
    let requestData = runPut $ putSessionData $ ExecRequest cmd
        request = ChannelRequest nr "exec" True requestData
    MS.lift $ sPutPacket socket request

    -- update the channelinfo with the correct handler function to handle the data of this exec request
    s <- MS.get
    let cih  = channelInfoHandler s
        cih' = cih { channelHandler = handleExecRequest }
        ret  = s { channelInfoHandler = cih' }
    return $ ret


-- | Handler for when we haven't sent a request yet
handleDefaultSession :: SshString -> Channel ChannelInfo
handleDefaultSession s = error $ "Handle: Session: " ++ (show s)

-- | This 'Channel' has sent an ExecuteCommand request, handle the return data!
handleExecRequest :: SshString -> Channel ChannelInfo
handleExecRequest s = do
    printDebugLifted logDebug "This is the result of an exec request:"
    let raw = B.unpack s
    MS.liftIO $ putStr $ map (toEnum . fromEnum) raw
    MS.get >>= return
