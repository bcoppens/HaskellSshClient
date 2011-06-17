{-# LANGUAGE OverloadedStrings #-}

module Ssh.Channel.Session (
      sessionHandler
)
where

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)

import Ssh.Packet
import Ssh.Channel
import Ssh.String

sessionHandler = ChannelHandler "session" handleSession

handleSession :: SshString -> Channel ChannelInfo
handleSession = error "Handle: Session"
