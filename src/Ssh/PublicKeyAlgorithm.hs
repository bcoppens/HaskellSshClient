-- | Interface for Public Key algorithms
module Ssh.PublicKeyAlgorithm (
    PublicKeyAlgorithm (..)
) where

import Ssh.String

-- TODO, certificates, etc?

-- | Defines information about a public key algorithm
--   For signing, this should be instantiated with the right private key info...
data PublicKeyAlgorithm = PublicKeyAlgorithm {
      publicKeyAlgorithmName :: SshString
    , verify :: SshString -> SshString -> Bool -- ^ Verify if a given public key (first argument) signed the data (second argument)
    , sign :: SshString -> SshString           -- ^ Sign the data
}

instance Show PublicKeyAlgorithm where
    show = show . publicKeyAlgorithmName
