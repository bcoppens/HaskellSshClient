module Ssh.Authentication (
      authenticate
    , AuthenticationService(..)
) where

import qualified Data.ByteString.Lazy as B

import Ssh.Transport

type SshString = B.ByteString

data AuthenticationService = AuthenticationService {
      authenticationName :: SshString
    , doAuthenticate :: SshConnection Bool -- Authentication succesful?
}

authenticate :: SshString -> SshString -> [AuthenticationService] -> SshConnection Bool
authenticate username service = error "Yo" -- do
    -- First of all, authenticate with the "none" method, so that it can fail and we see which 
