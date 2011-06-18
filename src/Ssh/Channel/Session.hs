{-# LANGUAGE OverloadedStrings #-}

-- | Support for interactive sessions, remote executions, etc. as per SSH Connection Protocol (RFC 4251) Section 6.
module Ssh.Channel.Session (
    -- * Default handler for sessions
      sessionHandler
    -- * Different requests for a session Channel
    , requestExec
    , requestShell
)
where

import Data.Binary.Get
import Data.Binary.Put

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B

import Ssh.Packet
import Ssh.Channel
import Ssh.String
import Ssh.Transport
import Ssh.NetworkIO
import Ssh.Debug

import Ssh.Channel.Session.Shell

-- | This is the default handler for a session
sessionHandler = ChannelHandler "session" handleDefaultSession

-- | Different kinds of sessions are supported
data SessionType =
    -- | Execute a remote command
      ExecuteCommand
    -- | Ask for a remote shell
    | RemoteShell

-- | Different kinds of request can be sent to the server
data SessionRequest =
    -- | Execute a remote command with the given string
      ExecRequest {
        execCommand :: SshString
      }
    -- | Request a shell
    | ShellRequest

-- | 'Put' for sending a request to the server with its associated payload
putSessionData :: SessionRequest -> Put
putSessionData (ExecRequest e) = do
    putString e

-- TODO: verify that this is an open "ssh-connection" channel when requesting?
-- TODO: when sending, wait until the remote's window size is large enough! Wait, and split in packets <= maxpacketsize if needed!

-- | Given the 'Socket' in the 'Channel' state, run the specified command remotely on this 'Channel'
requestExec :: SshString -> Channel ChannelInfo
requestExec cmd = do
    -- Request the "exec" command on this channel
    nr <- getLocalChannelNr
    let requestData = runPut $ putSessionData $ ExecRequest cmd
        request = ChannelRequest nr "exec" True requestData
    MS.lift $ sPutPacket request

    -- update the channelinfo with the correct handler function to handle the data of this exec request
    setChannelHandler handleExecRequest

-- | Handler for when we haven't sent a request yet
handleDefaultSession :: SshString -> Channel ChannelInfo
handleDefaultSession s = error $ "Handle: Session: " ++ (show s)

-- #### EXECUTE CHANNEL ####
-- | This 'Channel' has sent an ExecuteCommand request, handle the return data!
handleExecRequest :: SshString -> Channel ChannelInfo
handleExecRequest s = do
    printDebugLifted logDebug "This is the result of an exec request:"
    let raw = B.unpack s
    MS.liftIO $ putStr $ map (toEnum . fromEnum) raw
    MS.get >>= return
