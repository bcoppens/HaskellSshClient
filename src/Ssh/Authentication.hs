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
import Ssh.Debug

type SshString = B.ByteString

data AuthenticationService = AuthenticationService {
      authenticationName :: SshString
    , doAuthenticate :: Socket -> SshString -> SshString -> SshConnection Bool -- Authentication succesful?
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
    let supportedNames = authenticationsCanContinue response
        canContinue = filter (\s -> authenticationName s `elem` supportedNames) authServices
    loopSupported canContinue
    -- TODO! it is possible that there is partial succes, etc, report that/do sth with that?
    where loopSupported []             = return False
          loopSupported (askPass:rest) = do
            MS.liftIO $ printDebug $ "Trying authentication method " ++ (map (toEnum . fromEnum) $ B.unpack $ authenticationName askPass)
            ok <- doAuthenticate askPass socket username service
            case ok of
                True  -> return True
                False -> loopSupported rest
