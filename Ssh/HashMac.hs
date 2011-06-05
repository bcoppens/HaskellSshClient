{-# LANGUAGE OverloadedStrings #-}

module Ssh.HashMac (
      HashMac(..)
    , noHashMac
) where

import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy.Char8 () -- IsString instance for the above

type SshString = B.ByteString

data HashMac = HashMac {
      hashName :: SshString
    , hashFunction :: SshString -> SshString
    , hashSize :: Int
}

instance Show HashMac where
    show = show . hashName

noHashMac = HashMac "none" id 0 -- for the initial KEX
