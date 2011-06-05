module Ssh.HashMac (
      HashMac(..)
    , noHashMac
) where

import qualified Data.ByteString.Lazy.Char8 as B
type SshString = B.ByteString

data HashMac = HashMac {
      hashName :: SshString
    , hashFunction :: SshString -> SshString
    , hashSize :: Int
}

instance Show HashMac where
    show = B.unpack . hashName

noHashMac = HashMac (B.pack "none") id 0 -- for the initial KEX
