module Ssh.KeyExchange (
      KEXAlgorithm(..)
    , createKeyData
    , makeWord8
) where

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)

import qualified Data.ByteString.Lazy.Char8 as B

import Data.Word
import Data.Digest.Pure.SHA

import Ssh.Packet
import Ssh.ConnectionData

type SshString = B.ByteString

data KEXAlgorithm = KEXAlgorithm {
      kexName :: SshString
    , handleKex :: SshString -> SshString -> SshString -> (SshString -> SshString) -> (Socket -> IO Packet) -> Socket -> IO ConnectionData
}

instance Show KEXAlgorithm where
    show = B.unpack . kexName

makeWord8 x = map (toEnum . fromEnum) $ B.unpack x

createKeyData :: SshString -> SshString -> Char -> SshString -> [Word8]
createKeyData sharedSecret exchangeHash typeChar sId =
    makeWord8 $ createKeyData' {-sha1-} (B.concat [sharedSecret, exchangeHash]) (B.concat [B.pack [typeChar], sId])

createKeyData' :: SshString -> SshString -> SshString -- make sha1 configurable ### TODO
createKeyData' init append = B.concat [hashed, createKeyData' init hashed]
  where hashed = bytestringDigest $ sha1 $ B.concat [init, append]
