{-# LANGUAGE OverloadedStrings #-}

-- | Generic support for SSH Authentication Protocol (RFC 4252).
module Ssh.Authentication (
      authenticate
    , AuthenticationService(..)
) where

import qualified Data.ByteString.Lazy as B
import qualified Control.Monad.State as MS

import Data.List

import Ssh.Packet
import Ssh.Transport
import Ssh.Debug
import Ssh.String

-- | Defines how a specific authentication service works
data AuthenticationService = AuthenticationService {
      authenticationName :: SshString
    -- | Takes username, hostname, servicename. Returns if authentication was succesful
    , doAuthenticate :: SshString -> SshString -> SshString -> SshConnection Bool
}

-- | Authenticate over an 'SshConnection': a username and a service, given a list of supported 'AuthenticationService's
authenticate :: SshString -> SshString -> SshString -> [AuthenticationService] -> SshConnection Bool
authenticate username hostname service authServices = do
    -- First of all, authenticate with the "none" method, so that it can fail and we see which authentication possibilities are supported
    sPutPacket $ ServiceRequest "ssh-userauth" -- Request userauth service
    sPutPacket $ UserAuthRequest username service "none" ""
    response <- waitForPacket $ \p -> case p of UserAuthFailure _ _ -> True; _ -> False

    -- See which names we support that the server also can continue with
    let supportedNames = authenticationsCanContinue response
        canContinue = filter (\s -> authenticationName s `elem` supportedNames) authServices

    -- Now try out all supported methods
    loopSupported canContinue
    -- TODO! it is possible that there is partial succes, etc, report that/do sth with that?
    where loopSupported []             = return False
          loopSupported (askPass:rest) = do
            MS.liftIO $ printDebug logDebug $ "Trying authentication method " ++ (map (toEnum . fromEnum) $ B.unpack $ authenticationName askPass)
            ok <- doAuthenticate askPass username hostname service
            case ok of
                True  -> return True
                False -> loopSupported rest
