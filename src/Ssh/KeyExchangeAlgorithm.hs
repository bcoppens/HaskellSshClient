module Ssh.KeyExchangeAlgorithm (
      KeyExchangeAlgorithm (..)
    , createKeyData
    , makeWord8
) where

import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy.Char8 () -- IsString instance for the above

import Data.Word
import Data.Digest.Pure.SHA

import Ssh.Packet
import Ssh.Transport
import Ssh.ConnectionData
import Ssh.String
import Ssh.HostKeyAlgorithm

data KeyExchangeAlgorithm = KeyExchangeAlgorithm {
      kexName :: SshString
    , handleKex :: SshString -> SshString -> SshString -> SshString -> SshConnection ConnectionData
}

instance Show KeyExchangeAlgorithm where
    show = show . kexName

makeWord8 x = map (toEnum . fromEnum) $ B.unpack x

createKeyData :: SshString -> SshString -> Word8 -> SshString -> [Word8]
createKeyData sharedSecret exchangeHash typeChar sId =
    makeWord8 $ createKeyData' {-sha1-} (B.concat [sharedSecret, exchangeHash]) (B.concat [B.pack [typeChar], sId])

createKeyData' :: SshString -> SshString -> SshString -- make sha1 configurable ### TODO
createKeyData' init append = B.concat [hashed, createKeyData' init hashed]
  where hashed = bytestringDigest $ sha1 $ B.concat [init, append]
