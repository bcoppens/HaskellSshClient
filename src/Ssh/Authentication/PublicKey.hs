{-# LANGUAGE OverloadedStrings #-}

-- | (Basic/raw) Public Key authentication for a user according to RFCs 4252 (authentication part) and 4253 (definition of public key algos)
module Ssh.Authentication.PublicKey (
      publicKeyAuth
) where

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put

import Ssh.Packet
import Ssh.NetworkIO
import Ssh.Transport
import Ssh.Authentication
import Ssh.String

-- | Try authenticating with a given public key algorithm, a user at a host for a service.
publicKeyAuth algo = AuthenticationService "publickey" $ doAuth algo

-- TODO: password authentication SHOULD be disabled when no confidentiality (cipher == none) or no mac are used!

-- | Try authenticating a user at a host for a service with a given public key algorithm
doAuth :: () -> SshString -> SshString -> SshString -> SshConnection Bool
doAuth pubKeyAlgo username hostname servicename = do
    return False
