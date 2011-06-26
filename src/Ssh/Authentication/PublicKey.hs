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
import Ssh.PublicKeyAlgorithm
import Ssh.String

-- | Try authenticating with a given public key algorithm, a user at a host for a service.
publicKeyAuth algo = AuthenticationService "publickey" $ doAuth algo


-- | The public key signature is signing this value
pubKeySignOver :: SshString -> SshString -> SshString -> PublicKeyAlgorithm -> SshString
pubKeySignOver sessionid username servicename pubkey = runPut $ do
    -- We start with the session identifier
    putString sessionid
    -- Then comes the UserAuthRequest packet. Don't fill out the actual payload, we'll append it ourselves
    putPacket $ UserAuthRequest username servicename "publickey" ""
    -- What now comes is basically pubKeyPayloadAuthenticate without the putString signature. TODO, factor out?
    putBool True
    putString $ publicKeyAlgorithmName pubkey
    putString $ publicKey pubkey

-- TODO: first offer the public key, and ask if he will be accepted, to avoid useless signing overhead
-- TODO: be able to offer multiple public keys!

-- | The payload of the userauth_request when performing the actual authentication
pubKeyPayloadAuthenticate :: PublicKeyAlgorithm -> SshString -> SshString
pubKeyPayloadAuthenticate pubkey signature = runPut $ do
    putBool True                              -- We are authenticating
    putString $ publicKeyAlgorithmName pubkey -- Algorithm name
    putString $ publicKey pubkey              -- Public key
    putString signature                       -- The signature itself


-- TODO: password authentication SHOULD be disabled when no confidentiality (cipher == none) or no mac are used!

-- | Try authenticating a user at a host for a service with a given public key algorithm
doAuth :: PublicKeyAlgorithm -> SshString -> SshString -> SshString -> SshConnection Bool
doAuth pubkey username hostname servicename = do
    -- Make a signature with our current public key
    sessionid <- (B.pack . sessionId . connectionData) `liftM` MS.get
    let toSign = pubKeySignOver sessionid username servicename pubkey
    signature <- MS.liftIO $ sign pubkey toSign

    -- Send our signature to the server
    let payload = pubKeyPayloadAuthenticate pubkey signature
    sPutPacket $ UserAuthRequest username servicename "publickey" payload

    response <- sGetPacket

    return $ case response of
        UserAuthSuccess -> True
        _               -> False
