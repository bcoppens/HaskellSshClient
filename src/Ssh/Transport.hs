{-# LANGUAGE CPP #-}

-- | The generic part of SSH's Transport Layer Protocol (RFC 4253).
--   Uses crypto functions to encrypt/decrypt packets, figure out their sizes, and checks their HMAC
module Ssh.Transport (
    -- * Data Types
      SshTransport (..)
    , SshTransportInfo (..)
    , ConnectionData (..)
    , SshConnection (..)
    , mkTransportInfo
    -- * Reading/Writing 'Packet's over the network
    , sGetPacket
    , sPutPacket
    , waitForPacket
    -- * Encoding and decoding for 'Packet's
    , makeSshPacket
    , getSizes
#ifdef DEBUG
    -- * Debug/Verbose
    , showTrafficStats
#endif
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
import Ssh.NetworkIO
import Ssh.ConnectionData
import Ssh.Debug
import Ssh.String

-- | Information needed to encrypt and verify a packet in a single direction
data SshTransport = SshTransport {
      crypto :: CryptionAlgorithm
    , mac    :: HashMac
} deriving Show

data TrafficStats = TrafficStats {
      packets :: Int
    , totalBytes :: Int
    , packetBytes :: Int
    , paddingBytes :: Int
    , macBytes :: Int
} deriving Show

-- | Empty (0) traffic stats
emptyTraffic = TrafficStats 0 0 0 0 0

-- | The state of the SSH Transport info in two directions: server to client, and client to server. Includes the socket to send info over
data SshTransportInfo = SshTransportInfo {
      socket :: SshSocket
{-  , kex_alg :: KeyExchangeAlgorithm
    , serverhost_key_alg :: HostKeyAlgorithm -}
    , client2server :: SshTransport
    , clientVector :: [Word8]
    , clientSeq :: Int32
    , server2client :: SshTransport
    , serverVector :: [Word8]
    , serverSeq :: Int32
    -- compression
    -- languages

    , connectionData :: ConnectionData

#ifdef DEBUG
    , c2sStats :: TrafficStats
    , s2cStats :: TrafficStats
#endif
} deriving Show

-- | Because the contents/signature of a SshTransportInfo vary according to -DDEBUG, provide a convenient wrapper constructor that is fixed in its signature
mkTransportInfo s c2s cv cs s2c sv ss cd =
    SshTransportInfo s c2s cv cs s2c sv ss cd
#ifdef DEBUG
        emptyTraffic emptyTraffic
#endif

-- | We keep around the SSH Transport State when interacting with the server (it changes for every packet sent/received)
type SshConnection = MS.StateT SshTransportInfo IO

-- | Type so we can easily switch wich stats to edit
data LogStats = C2S | S2C
    deriving Eq

-- | Log stats: automatically adds a packet. Other arguments: total bytes, packetbytes, paddingbytes, macbytes
logStats :: LogStats -> Int -> Int -> Int -> Int -> SshConnection ()
#ifdef DEBUG
logStats l tb packb padb macb | l == C2S = MS.modify $ \i -> i { c2sStats = inc $ c2sStats i }
                              | l == S2C = MS.modify $ \i -> i { s2cStats = inc $ s2cStats i }
                              where
                                inc stats = stats {
                                    packets      = 1 + packets stats,
                                    totalBytes   = tb + totalBytes stats,
                                    packetBytes  = packb + packetBytes stats,
                                    paddingBytes = padb + paddingBytes stats,
                                    macBytes     = macb + macBytes stats
                                }
#else
logStats _ _ _ _ _ = return ()
#endif

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
sPutPacket :: ClientPacket -> SshConnection ()
sPutPacket packet = do
    transportInfo <- MS.get
    let sock = socket transportInfo
        transport = client2server transportInfo
        rawPacket = makeSshPacket transport $ runPut $ putPacket packet
        bs = blockSize $ crypto $ client2server transportInfo
        enc = encrypt $ crypto $ client2server transportInfo
        -- Compute the HMAC over prepending the sequence number before the encoded (but unencrypted) packet
        hmac = mac $ client2server transportInfo
        macLen = hashSize hmac
        macKeySize = hashKeySize hmac
        macKey = take macKeySize $ client2ServerIntKey $ connectionData transportInfo
        macFun = hashFunction $ mac $ client2server transportInfo
        cseq = runPut $ putWord32 $ (toEnum . fromEnum) $ clientSeq transportInfo
        macBytes = B.unpack $ B.append cseq rawPacket
        computedMac = macFun macKey macBytes

    -- Encrypt packet, and send it. Send the HMAC afterwards
    encBytes <- encryptBytes $ B.unpack rawPacket
    MS.liftIO $ sockWriteBytes sock $ B.pack encBytes
    MS.liftIO $ sockWriteBytes sock $ B.pack computedMac

    -- Debug/Logging
    printDebugLifted logDebugExtended $ "Sent packet: " ++ show packet
    let macBytes     = length computedMac
        totalBytes   = macBytes + length encBytes
        packetBytes  = (toEnum . fromEnum) $ B.length $ runPut $ putPacket packet
        paddingBytes = length encBytes - packetBytes
    logStats C2S totalBytes packetBytes paddingBytes macBytes

    MS.modify $ \ti -> ti { clientSeq = 1 + clientSeq ti }


-- | Read a packet from the socket, decrypt it/checks MAC if needed, and decodes into a real 'Packet'
sGetPacket :: SshConnection ServerPacket
sGetPacket = do
    transportInfo <- MS.get
    let sock = socket transportInfo
        transport = server2client transportInfo
        bs = blockSize $ crypto $ server2client transportInfo
        smallSize = max 5 bs -- We have to decode at least 5 bytes to read the sizes of this packet. We might need to decode more to take cipher size into account
        getBlock size = MS.liftIO $ B.unpack `liftM` sockReadBytes sock size
        dec = decrypt $ crypto $ server2client transportInfo
        -- HMAC tools
        hmac = mac $ server2client transportInfo
        macLen = hashSize hmac
        macKeySize = hashKeySize hmac
        macKey = take macKeySize $ server2ClientIntKey $ connectionData transportInfo
        macFun = hashFunction $ mac $ server2client transportInfo

    -- Get and decrypt the first block of data from this packet, which contains the size fields
    firstBlock <- getBlock smallSize
    firstBytes <- decryptBytes dec firstBlock
    let (packlen, padlen) = getSizes firstBytes
        nextBytes = B.pack $ drop 5 firstBytes

    printDebugLifted logLowLevelDebug $ show (packlen, padlen)

    -- Now get and decrypt the remainder of the packet (including padding!) using the decrypted size fields data
    let payloadRestSize = packlen - padlen - 1 - (smallSize - 5) -- -1 because we already read the padlen field.
        packetRestSize = payloadRestSize + padlen
    restBytes <- getBlock packetRestSize
    restBytesDecrypted <- decryptBytes dec $ restBytes

    -- Compute the HMAC ourselves, and check if corresponds to the HMAC appended to the packet on the wire
    macBytes <- getBlock macLen
    let restPacketBytes = take payloadRestSize restBytesDecrypted
        sseq = runPut $ putWord32 $ (toEnum . fromEnum) $ serverSeq transportInfo
        toMacBytes = (B.unpack sseq) ++ firstBytes ++ restBytesDecrypted -- includes length fields and padding as well
        computedMac = macFun macKey toMacBytes
        macOK = macBytes == computedMac

    if not macOK
        then printDebugLifted logWarning "Received MAC NOT OK!"
        else printDebugLifted logLowLevelDebug $
                "Got " ++ show macLen ++ " bytes of mac\n" ++ (debugRawStringData $ B.pack macBytes)
                       ++ "\nComputed mac as:\n" ++ (debugRawStringData $ B.pack computedMac) ++ "\nMAC OK?? " ++ show macOK

    -- Decode the packet from the payload data
    let payload = B.append nextBytes $ B.pack restPacketBytes
        packet = (runGet getPacket payload) :: ServerPacket

    printDebugLifted logDebugExtended $ "Got packet: " ++ show packet

    MS.modify $ \ti -> ti { serverSeq = 1 + serverSeq ti }

    return $ annotatePacketWithPayload packet payload


-- [!] TODO this should throw some ignored packets to a higher level (i.e. a rekeying request)!
-- | Ignore all packets until one is found matching the condition, and return that
waitForPacket :: (Packet -> Bool) -> SshConnection Packet
waitForPacket cond = do
    loop
    where
        loop = do
            packet <- sGetPacket
            if cond packet
                then return packet
                else do
                    printDebugLifted logDebug $ "Ignoring packet: " ++ show packet
                    loop

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

#ifdef DEBUG
-- | Show the stats of this connection
showTrafficStats :: SshTransportInfo -> String
showTrafficStats info = "Stats:\nClient to Server: " ++ show (c2sStats info) ++ "\nServer to Client: " ++ show (s2cStats info)
#endif
