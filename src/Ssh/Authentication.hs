{-# LANGUAGE OverloadedStrings #-}

module Ssh.Authentication (
      authenticate
    , AuthenticationService(..)
) where

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)

import qualified Data.ByteString.Lazy as B
import qualified Control.Monad.State as MS

import Data.List

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
    let c2s = client2server transportInfo
        s2c = server2client transportInfo
    -- First of all, authenticate with the "none" method, so that it can fail and we see which authentication possibilities are supported
    sPutPacket c2s socket $ ServiceRequest "ssh-userauth" -- Request userauth service
    sPutPacket c2s socket $ UserAuthRequest username service "none" ""
    response <- waitForPacket c2s socket $ \p -> case p of UserAuthFailure _ _ -> True; _ -> False
    let  canContinue = intersect (map authenticationName authServices) $ authenticationsCanContinue response
    case canContinue of
        []    -> return False
        (x:_) -> return True
