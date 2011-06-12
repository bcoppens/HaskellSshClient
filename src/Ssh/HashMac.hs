{-# LANGUAGE OverloadedStrings #-}

module Ssh.HashMac (
      HashMac(..)
    , noHashMac
    , sha1HashMac
) where

import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy.Char8 () -- IsString instance for the above
import Data.Word
import Data.HMAC

type SshString = B.ByteString

data HashMac = HashMac {
      hashName :: SshString
      -- secret key -> message -> HMAC
    , hashFunction :: [Word8] -> [Word8] -> [Word8]
    , hashSize :: Int
    , hashKeySize :: Int
}

instance Show HashMac where
    show = show . hashName

none _ _ = []

noHashMac = HashMac "none" none 0 0 -- for the initial KEX
sha1HashMac = HashMac "hmac-sha1" hmac_sha1 20 20
