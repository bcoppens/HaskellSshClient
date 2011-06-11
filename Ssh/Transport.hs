module Ssh.Transport (
      SshTransport (..)
    , SshTransportInfo (..)
    , ConnectionData (..)
    , SshConnection (..)
    , sGetPacket
    , makeSshPacket
    , getSizes
) where

import Control.Monad
import qualified Control.Monad.State as MS

import Network
import Data.Int

import qualified Data.ByteString.Lazy as B

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

import Ssh.Cryption
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
{-      kex_alg :: KeyExchangeAlgorithm
    ,-} serverhost_key_alg :: HostKeyAlgorithm

    , client2server :: SshTransport
    , clientVector :: [Word8]
    , clientSeq :: Int32
    , server2client :: SshTransport
    , serverVector :: [Word8]
    , serverSeq :: Int32
    -- compression
    -- languages

    , connectionData :: ConnectionData
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

nullByte = toEnum $ fromEnum '\0'

makeSshPacket :: SshTransport -> SshString -> SshString
makeSshPacket t payload = makeSshPacket' t payload $ B.pack $ replicate (paddingLength t $ fromEnum $ B.length payload) nullByte -- TODO make padding random

sGetPacket :: SshTransport -> Socket -> SshConnection ServerPacket
sGetPacket transport s = do
    transportInfo <- MS.get
    let bs = blockSize $ crypto $ server2client transportInfo
        smallSize = max 5 bs -- We have to decode at least 5 bytes to read the sizes of this packet. We might need to decode more to take cipher size into account
        getBlock size = MS.liftIO $ B.unpack `liftM` sockReadBytes s size
        dec = decrypt $ crypto $ server2client transportInfo
    firstBlock <- getBlock smallSize
    MS.liftIO $ putStrLn $ show $ B.pack firstBlock
    firstBytes <- decryptBytes dec firstBlock
    MS.liftIO $ putStrLn $ show $ B.pack firstBytes
    let (packlen, padlen) = getSizes firstBytes
        nextBytes = B.pack $ drop 5 firstBytes
    MS.liftIO $ putStrLn $ show (packlen, padlen)
    let payloadRestSize = packlen - padlen - 1 - (smallSize - 5) -- -1 because we already read the padlen field.
        packetRestSize = payloadRestSize + padlen
    restBytes <- getBlock packetRestSize
    let packetBytes = take payloadRestSize restBytes
    restBytesDecrypted <- decryptBytes dec $ packetBytes
    -- TODO verify MAC
    let payload = B.append nextBytes $ B.pack restBytesDecrypted
        packet = (runGet getPacket payload) :: ServerPacket
    return $ annotatePacketWithPayload packet payload

-- We decode the initial block
-- Packet Length is the lenght of the (encrypted, no mac added) packet, WITHOUT the packet_length field, WITH padding_length field!
-- This means that the length of the payload == packetlen - padlen - 1
getSizes :: [Word8] -> (Int, Int) -- (packetlen, padlen)
getSizes block = runGet getSizes' $ B.pack block

getSizes' :: Get (Int, Int)
getSizes' = do
    packl <- getWord32
    padl  <- getWord8
    return (fromEnum packl, fromEnum padl)

{-
encryptBytes :: [Word8] -> [Word8] -> SshConnection [Word8]
encryptBytes key s = do
    transport <- MS.get
    let c2s = client2server transport
        v = clientVector transport
        crypt = encrypt $ crypto c2s
        encrypted = crypt key $ cbcEnc v s
    MS.put $ transport { clientVector = encrypted }
    return encrypted
-}

decryptBytes :: CryptoFunction -> [Word8] -> SshConnection [Word8]
decryptBytes c s = do
    transportInfo <- MS.get
    let s2c = server2client transportInfo
        v = serverVector transportInfo
        crypt = decrypt $ crypto s2c
        key = server2ClientEncKey $ connectionData transportInfo
        (decrypted, newState) = MS.runState (crypt key s) $ CryptionInfo v
    MS.put $ transportInfo { serverVector = stateVector newState }
    return decrypted

