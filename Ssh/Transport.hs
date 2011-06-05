module Ssh.Transport (
      SshTransport (..)
    , SshTransportInfo (..)
    , ConnectionData (..)
    , sGetPacket
    , makeSshPacket
    , getSizes
    , getSmallBlock
) where

import Network.BSD ( HostEntry (..), getProtocolNumber, getHostByName
                   , hostAddress
                   )
import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import Network.Socket.ByteString.Lazy

import Control.Monad
import qualified Control.Monad.State as MS
import Data.List
import Data.Maybe
import Data.Monoid
import Data.Bits

import Network
import System.IO
import System.Random
import Data.Char
import Data.Word
import Data.LargeWord
import Data.Int

import qualified Data.ByteString.Lazy.Char8 as B

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put


import Ssh.Cryption
import Ssh.KeyExchange
import Ssh.HashMac
import Ssh.Packet
import Ssh.HostKeyAlgorithm
import Ssh.NetworkIO
import Ssh.ConnectionData

type SshString = B.ByteString


data SshTransport = SshTransport {
      crypto :: CryptionAlgorithm
    , mac    :: HashMac
} deriving Show

data SshTransportInfo = SshTransportInfo {
      kex_alg :: KEXAlgorithm
    , serverhost_key_alg :: HostKeyAlgorithm

    , client2server :: SshTransport
    , clientVector :: [Word8]
    , clientSeq :: Int32
    , server2client :: SshTransport
    , serverVector :: [Word8]
    , serverSeq :: Int32
    -- compression
    -- languages
} deriving Show

type SshConnection = MS.StateT SshTransportInfo IO

makeSshPacketWithoutMac :: SshTransport -> SshString -> SshString -> SshString
makeSshPacketWithoutMac t payload padding = runPut $ do
    let pl = B.append payload padding
    put $ encodeAsWord32 $ 1 + B.length pl -- packetlen
    put $ encodeAsWord8 $ B.length padding -- padlen
    putRawByteString pl

makeSshPacket' :: SshTransport -> SshString -> SshString -> SshString
makeSshPacket' t payload padding = runPut $ do
    let noMac = makeSshPacketWithoutMac t payload padding
    putRawByteString noMac
    --put $ (docrypt . crypto) t $ noMac
    --put $ (hashFunction . mac) t $ noMac

{- multiple of max (8, cipherblocksize), and 4 <= len <= 255 -}
paddingLength :: SshTransport -> Int -> Int
paddingLength t packLen = 8 + (-packLen - 5) `mod` (max 8 (blockSize $ crypto t)) -- TODO 8+ ...


makeSshPacket :: SshTransport -> SshString -> SshString
makeSshPacket t payload = makeSshPacket' t payload $ B.pack $ replicate (paddingLength t $ fromEnum $ B.length payload) '\0' -- TODO make padding random

sGetPacket :: (Get Packet) -> SshTransport -> Socket -> IO ServerPacket
sGetPacket kih t s = do
    (packlen, padlen) <- getSizes s t
    putStrLn $ show (packlen, padlen)
    payload <- sockReadBytes s (packlen - padlen - 1) -- TODO decode as block
    padding <- sockReadBytes s padlen
    -- TODO verify MAC
    let packet = (runGet (getPacket kih) payload) :: ServerPacket
    return $ annotatePacketWithPayload packet payload

getSmallBlock :: Socket -> SshTransport -> Int -> IO SshString
getSmallBlock s _ size = sockReadBytes s size -- TODO stuff with decoding blocks and all that

-- We decode the initial block
getSizes :: Socket -> SshTransport -> IO (Int, Int) -- (packetlen, transportlen)
getSizes h t = do
    sb <- getSmallBlock h t 5
    return $ runGet getSizes' sb

getSizes' :: Get (Int, Int)
getSizes' = do
    packl <- getWord32
    padl  <- getWord8
    return (fromEnum packl, fromEnum padl)
