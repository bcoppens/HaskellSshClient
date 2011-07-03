-- | A wrapper around a PublicKeyAlgorithm that is used to keep track of the host keys.
--   For example, it can store (on disk) a mapping of known hosts+keys, or ask the user if a public key is indeed correct for a server
module Ssh.HostKeyAlgorithm (
    HostKeyAlgorithm(..)
) where

import Ssh.String

-- | Checks for a servername the host key (potentially including certificates), while perhaps reading from file whether this key corresponds to what we know,
--   and whether the signature is actually signed by said key.
data HostKeyAlgorithm = HostKeyAlgorithm {
    checkHostKey :: SshString -> SshString -> SshString -> IO Bool -- ^ host name -> key/certs -> signature -> ok?
}
