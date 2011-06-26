-- | Interface for Public Key algorithms
module Ssh.PublicKeyAlgorithm (
    PublicKeyAlgorithm (..)
) where

import Ssh.String

-- TODO, certificates, etc?

-- | Defines information about a public key algorithm
--   For signing, this should be instantiated with the right private key info...
--   Currently these are in IO because OpenSSL.DSA also uses IO
data PublicKeyAlgorithm = PublicKeyAlgorithm {
      publicKeyAlgorithmName :: SshString
    , verify :: SshString -> SshString -> IO Bool -- ^ Verify if a given public key (first argument) signed the data (second argument)
    , sign :: SshString -> IO SshString           -- ^ Sign the data
    , publicKey :: IO SshString                   -- ^ The public key corresponding to the private key used in 'sign
}

instance Show PublicKeyAlgorithm where
    show = show . publicKeyAlgorithmName
