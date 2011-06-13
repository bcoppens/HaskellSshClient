{-# LANGUAGE OverloadedStrings #-}

module Ssh.Authentication (
      authenticate
    , AuthenticationService(..)
) where

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)

import qualified Data.ByteString.Lazy as B
import qualified Control.Monad.State as MS

import Ssh.Packet
import Ssh.Transport

type SshString = B.ByteString

data AuthenticationService = AuthenticationService {
      authenticationName :: SshString
    , doAuthenticate :: SshString -> SshConnection Bool -- Authentication succesful?
}

authenticate :: Socket -> SshString -> SshString -> [AuthenticationService] -> SshConnection Bool
authenticate socket username service authServices = do
    transportInfo <- MS.get
    let transport = client2server transportInfo
    -- First of all, authenticate with the "none" method, so that it can fail and we see which authentication possibilities are supported
    sPutPacket transport socket $ UserAuthRequest username service "none" ""
    response <- sGetPacket transport socket
    return False