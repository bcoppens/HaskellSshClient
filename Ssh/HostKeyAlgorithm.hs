module Ssh.HostKeyAlgorithm (
    HostKeyAlgorithm (..)
) where

import qualified Data.ByteString.Lazy as B
type SshString = B.ByteString

data HostKeyAlgorithm = HostKeyAlgorithm {
    hostKeyAlgorithmName :: SshString
    --doHKA :: ()
}

instance Show HostKeyAlgorithm where
    show = show . hostKeyAlgorithmName
