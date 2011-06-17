{-# LANGUAGE OverloadedStrings #-}

module Ssh.Channel.Session (
      sessionHandler
    , requestExec
)
where

import Data.Binary.Get
import Data.Binary.Put

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import qualified Control.Monad.State as MS

import Ssh.Packet
import Ssh.Channel
import Ssh.String
import Ssh.Transport
import Ssh.NetworkIO

sessionHandler = ChannelHandler "session" handleSession

data SessionData =
      ExecRequest {
        execCommand :: SshString
      }

putSessionData :: SessionData -> Put
putSessionData (ExecRequest e) = do
    putString e

requestExec :: Socket -> SshString -> Channel ChannelInfo
requestExec socket cmd = do
    nr <- getLocalChannelNr
    let requestData = runPut $ putSessionData $ ExecRequest cmd
        request = ChannelRequest nr "exec" True requestData
    MS.lift $ sPutPacket socket request
    s <- MS.get
    return s

handleSession :: SshString -> Channel ChannelInfo
handleSession = error "Handle: Session"


