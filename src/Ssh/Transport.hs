-- | The generic part of SSH's Transport Layer Protocol (RFC 4253).
--   Uses crypto functions to encrypt/decrypt packets, figure out their sizes, and checks their HMAC
module Ssh.Transport (
    -- * Data Types
      SshTransport (..)
    , SshTransportInfo (..)
    , ConnectionData (..)
    , SshConnection (..)
    -- * Reading/Writing 'Packet's over the network
    , sGetPacket
    , sPutPacket
    , waitForPacket
    -- * Encoding and decoding for 'Packet's
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
import Ssh.Debug

type SshString = B.ByteString

-- | Information needed to encrypt and verify a packet in a single direction
data SshTransport = SshTransport {
      crypto :: CryptionAlgorithm
    , mac    :: HashMac
} deriving Show

-- | The state of the SSH Transport info in two directions: server to client, and client to server
data SshTransportInfo = SshTransportInfo {
{-      kex_alg :: KeyExchangeAlgorithm
    , serverhost_key_alg :: HostKeyAlgorithm

    ,-} client2server :: SshTransport
    , clientVector :: [Word8]
    , clientSeq :: Int32
    , server2client :: SshTransport
    , serverVector :: [Word8]
    , serverSeq :: Int32
    -- compression
    -- languages

    , connectionData :: ConnectionData
} deriving Show

-- | We keep around the SSH Transport State when interacting with the server (it changes for every packet sent/received)
type SshConnection = MS.StateT SshTransportInfo IO

-- | Wrap an SSH packet payload with a length header and its padding
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

{- Pad with len pad bytes so that size of |packetlen|padlen|payload|padding| is multiple of max (8, cipherblocksize), and 4 <= len <= 255 -}
-- TODO: randomize?
-- | Compute the length of padding needed for a packet of the given size, for the specified transport
paddingLength :: SshTransport -> Int -> Int
paddingLength t packLen | minPadding < 4  = 4 + paddingLength t (packLen + 4)
                        | otherwise       = minPadding
    where minPadding = multipleOf - ((packLen + 5) `mod` multipleOf)
          bs         = blockSize $ crypto t
          multipleOf = max 8 bs

nullByte = toEnum $ fromEnum '\0'

-- | Given an SSH packet payload and a transport, make a real SSH packet out of it, including size and padding fields
makeSshPacket :: SshTransport -> SshString -> SshString
makeSshPacket t payload = makeSshPacket' t payload $ B.pack $ replicate padLen nullByte -- TODO make padding random
    where
        padLen = (paddingLength t $ fromEnum $ B.length payload)


-- | Take a 'Packet', encode it to bytes that can be sent over the wire. Applies necessary encryption and MAC codes, and sends over the socket
sPutPacket :: Socket -> ClientPacket -> SshConnection ()
sPutPacket socket packet = do
    transportInfo <- MS.get
    let transport = client2server transportInfo
        rawPacket = makeSshPacket transport $ runPut $ putPacket packet
        bs = blockSize $ crypto $ client2server transportInfo
        enc = encrypt $ crypto $ client2server transportInfo
        hmac = mac $ client2server transportInfo
        macLen = hashSize hmac
        macKeySize = hashKeySize hmac
        macKey = take macKeySize $ client2ServerIntKey $ connectionData transportInfo
        macFun = hashFunction $ mac $ client2server transportInfo
        cseq = runPut $ putWord32 $ (toEnum . fromEnum) $ clientSeq transportInfo
        macBytes = B.unpack $ B.append cseq rawPacket
        computedMac = macFun macKey macBytes
    encBytes <- encryptBytes $ B.unpack rawPacket
    MS.liftIO $ sockWriteBytes socket $ B.pack encBytes
    MS.liftIO $ sockWriteBytes socket $ B.pack computedMac

    printDebugLifted $ "Sent packet: " ++ show packet

    MS.modify $ \ti -> ti { clientSeq = 1 + clientSeq ti }

-- | Read a packet from the socket, decrypt it/checks MAC if needed, and decodes into a real 'Packet'
sGetPacket :: Socket -> SshConnection ServerPacket
sGetPacket s = do
    transportInfo <- MS.get
    let transport = server2client transportInfo
        bs = blockSize $ crypto $ server2client transportInfo
        smallSize = max 5 bs -- We have to decode at least 5 bytes to read the sizes of this packet. We might need to decode more to take cipher size into account
        getBlock size = MS.liftIO $ B.unpack `liftM` sockReadBytes s size
        dec = decrypt $ crypto $ server2client transportInfo
        hmac = mac $ server2client transportInfo
        macLen = hashSize hmac
        macKeySize = hashKeySize hmac
        macKey = take macKeySize $ server2ClientIntKey $ connectionData transportInfo
        macFun = hashFunction $ mac $ server2client transportInfo
    firstBlock <- getBlock smallSize
    firstBytes <- decryptBytes dec firstBlock
    let (packlen, padlen) = getSizes firstBytes
        nextBytes = B.pack $ drop 5 firstBytes
    printDebugLifted $ show (packlen, padlen)
    let payloadRestSize = packlen - padlen - 1 - (smallSize - 5) -- -1 because we already read the padlen field.
        packetRestSize = payloadRestSize + padlen
    restBytes <- getBlock packetRestSize
    restBytesDecrypted <- decryptBytes dec $ restBytes
    macBytes <- getBlock macLen
    let restPacketBytes = take payloadRestSize restBytesDecrypted
        sseq = runPut $ putWord32 $ (toEnum . fromEnum) $ serverSeq transportInfo
        toMacBytes = (B.unpack sseq) ++ firstBytes ++ restBytesDecrypted -- includes length fields and padding as well
        computedMac = macFun macKey toMacBytes
        macOK = macBytes == computedMac

    printDebugLifted $ "Got " ++ show macLen ++ " bytes of mac\n" ++ (debugRawStringData $ B.pack macBytes) ++ "\nComputed mac as:\n" ++ (debugRawStringData $ B.pack computedMac) ++ "\nMAC OK?? " ++ show macOK

    let payload = B.append nextBytes $ B.pack restPacketBytes
        packet = (runGet getPacket payload) :: ServerPacket

    printDebugLifted $ "Got packet: " ++ show packet

    MS.modify $ \ti -> ti { serverSeq = 1 + serverSeq ti }
    return $ annotatePacketWithPayload packet payload

-- [!] TODO this should throw some ignored packets to a higher level (i.e. a rekeying request)!
-- | Ignore all packets until one is found matching the condition, and return that
waitForPacket :: Socket -> (Packet -> Bool) -> SshConnection Packet
waitForPacket socket cond = do
    let getter = sGetPacket socket
    loop getter
    where
        loop getter = do
            packet <- getter
            if cond packet
                then return packet
                else do
                    printDebugLifted $ "Ignoring packet: " ++ show packet
                    loop getter

-- We decode the initial block
-- Packet Length is the lenght of the (encrypted, no mac added) packet, WITHOUT the packet_length field, WITH padding_length field!
-- This means that the length of the payload == packetlen - padlen - 1
-- | Return a tuple of (packet length, padding length) from the header of an SSH packet
getSizes :: [Word8] -> (Int, Int) -- (packetlen, padlen)
getSizes block = runGet getSizes' $ B.pack block

-- | Actually do the reading for 'getSizes'
getSizes' :: Get (Int, Int)
getSizes' = do
    packl <- getWord32
    padl  <- getWord8
    return (fromEnum packl, fromEnum padl)

-- | Encrypt bytes with the encryption specified for client to server, keeping the state needed for CBC
encryptBytes :: [Word8] -> SshConnection [Word8]
encryptBytes s = do
    transportInfo <- MS.get
    let c2s = client2server transportInfo
        v = clientVector transportInfo
        crypt = encrypt $ crypto c2s
        key = client2ServerEncKey $ connectionData transportInfo
        (encrypted, newState) = MS.runState (crypt key s) $ CryptionInfo v
    MS.put $ transportInfo { clientVector = stateVector newState }
    return encrypted

-- | Decrypt bytes with the decryption specified for server to client, keeping the state needed for CBC
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

