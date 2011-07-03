-- | Interface for Public Key algorithms
module Ssh.PublicKeyAlgorithm (
    PublicKeyAlgorithm (..)
) where

import Ssh.String

-- TODO, certificates, etc?
-- TODO: key fingerprint algorithms (graphics, etc)

-- | Defines information about a public key algorithm
--   For signing, this should be instantiated with the right private key info...
--   Currently these are in IO because OpenSSL.DSA also uses IO
data PublicKeyAlgorithm = PublicKeyAlgorithm {
      publicKeyAlgorithmName :: SshString
    , verify :: SshString -> SshString -> SshString -> IO Bool -- ^ Verify if a given public key (first argument) signed the data (second argument) resulting in a signature (3rd argument)
    , sign :: SshString -> IO SshString           -- ^ Sign the data
    , publicKey :: SshString                      -- ^ The public key corresponding to the private key used in 'sign
    , fingerprint :: SshString -> SshString       -- ^ Get the fingerprint of the public key in the first argument
}

instance Show PublicKeyAlgorithm where
    show = show . publicKeyAlgorithmName
