import Network
import System.IO
import System.Random
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Char
import Data.Word
import Control.Monad
import qualified Control.Monad.State as MS
import Data.List
import Data.Maybe
import Data.Monoid
import Data.Bits
import qualified Data.ByteString.Lazy.Char8 as B
import qualified Data.ByteString.Char8 as BS


import Data.Int
import Network.BSD ( HostEntry (..), getProtocolNumber, getHostByName
                   , hostAddress
                   )
import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import Network.Socket.ByteString.Lazy

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers

import Data.HMAC
import Data.Digest.Pure.SHA
import qualified Codec.Encryption.AES as AES
import Codec.Utils
import Data.LargeWord

import Debug.Trace
--debug = traceShow
debug = putStrLn

sockReadBytes :: Socket -> Int -> IO B.ByteString
sockReadBytes s c = rrb s (fromIntegral c) mempty
    where
        rrb :: Socket -> Int64 -> B.ByteString -> IO B.ByteString
        rrb sock cnt str | B.length str < fromIntegral cnt = recv sock cnt >>= \got -> rrb sock cnt (B.append str got)
                         | otherwise                       = return str

sockReadLine' :: Socket -> B.ByteString -> IO B.ByteString
sockReadLine' socket string = do
    got <- recv socket 1
    if B.unpack got == "\n"
        then return string
        else sockReadLine' socket $ B.append string got

sockReadLine :: Socket -> IO B.ByteString
sockReadLine s = sockReadLine' s mempty

--encodeAsWord32 :: (Integral a, Num a) => a -> Word32
encodeAsWord32 i = fromInteger $ toInteger i :: Word32
encodeAsWord8 i = fromInteger $ toInteger i :: Word8

putRawByteString b = forM_ (map (fromInteger . toInteger . ord) $ B.unpack b) (put :: Word8 -> Put)

getWord32 = getWord32be
putWord32 = putWord32be

clientVersionString = "SSH-2.0-BartSSHaskell-0.0.1 This is crappy software!\r\n"

type SshString = B.ByteString

data CryptionAlgorithm = CryptionAlgorithm {
      cryptoName :: SshString
    , encrypt :: [Word8] -> [Word8] -> [Word8] -- encrypt: key -> plaintext -> result
    , decrypt :: [Word8] -> [Word8] -> [Word8] -- encrypt: key -> ciphertext -> result
    , blockSize :: Int -- can be 0 for stream ciphers
}


chunkUpString :: Int -> SshString -> [[Word8]] -- bytesPerChunk string
chunkUpString bpc s = chunkIt bytes []
    where bytes = map (toEnum . fromEnum) $ B.unpack s
          chunkIt :: [Word8] -> [[Word8]] -> [[Word8]]
          chunkIt b acc | todo == []  = new
                        | otherwise   = chunkIt todo new
                        where (chunk, todo)   = splitAt bpc b
                              new             = acc ++ [chunk] -- TODO
{-
chunkString :: Integer -> Int -> SshString
chunkString msg blockSize = 


convertCharToInteger :: [Char] -> Integer
convertCharToInteger c = convertCharToInteger' c 0
    where
        convertCharToInteger' :: [Char] -> Integer -> Integer
        convertCharToInteger' [] a = a
        convertCharToInteger' (x:xs) a = convertCharToInteger' xs (256 * a + (toEnum (fromEnum x)))
-}

convertString bs = toEnum . fromIntegral . (fromOctets 256)
--reconvertString s = B.pack $ map (toEnum . fromEnum) $ toOctets 256 s
reconvertString s = toOctets 256 s

aesEncrypt :: Int -> [Word8] -> [Word8] -> [Word8]
aesEncrypt 256 key plain =
    reconvertString $ AES.encrypt (convertString 32 key :: Word256) (convertString 32 plain :: Word128)

aesDecrypt :: Int -> [Word8] -> [Word8] -> [Word8]
aesDecrypt 256 key enc =
    reconvertString $ AES.decrypt (convertString 32 key :: Word256) (convertString 32 enc :: Word128)

instance Show CryptionAlgorithm where
    show = B.unpack . cryptoName

noCrypto = CryptionAlgorithm (B.pack "none") (\_ -> id) (\_ -> id) 0 -- for the initial KEX

clientCryptos = [ (CryptionAlgorithm (B.pack "aes256-cbc") (aesEncrypt 256) (aesDecrypt 256) 128) ]

data HashMac = HashMac {
      hashName :: SshString
    , hashFunction :: SshString -> SshString
    , hashSize :: Int
}

instance Show HashMac where
    show = B.unpack . hashName

noHashMac = HashMac (B.pack "none") id 0 -- for the initial KEX

clientHashMacs = [ HashMac (B.pack "hmac-sha1") (error "OEPS") 0 ]

data KEXAlgorithm = KEXAlgorithm {
      kexName :: SshString
    , handleKex :: Packet -> Packet -> SshTransport -> Socket -> IO ConnectionData
}

instance Show KEXAlgorithm where
    show = B.unpack . kexName

data HostKeyAlgorithm = HostKeyAlgorithm {
    hostKeyAlgorithmName :: SshString
    --doHKA :: ()
}

instance Show HostKeyAlgorithm where
    show = B.unpack . hostKeyAlgorithmName

rsaHostKey = HostKeyAlgorithm (B.pack "ssh-rsa")
clientHostKeys = [rsaHostKey]

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

cbcDec :: [Word8] -> [Word8] -> [Word8]
cbcDec x y = map (uncurry xor) $ zip x y

cbcEnc = cbcDec

encryptBytes :: [Word8] -> [Word8] -> SshConnection [Word8]
encryptBytes key s = do
    transport <- MS.get
    let c2s = client2server transport
        v = clientVector transport
        crypt = encrypt $ crypto c2s
        encrypted = crypt key $ cbcEnc v s
    MS.put $ transport { clientVector = encrypted }
    return encrypted

decryptBytes :: [Word8] -> [Word8] -> SshConnection [Word8]
decryptBytes key s = do
    transport <- MS.get
    let s2c = server2client transport
        v = serverVector transport
        crypt = decrypt $ crypto s2c
        decrypted = crypt key s
    MS.put $ transport { serverVector = s }
    return $ cbcDec v decrypted

data NameList = NameList {
    names :: [SshString]
}

instance Show NameList where
    show nl = show $ map B.unpack $ names nl

putNameList :: NameList -> Put
putNameList l = do
    let fullList = B.intercalate (B.singleton ',') $ names l
    put $ encodeAsWord32 $ B.length fullList
    putRawByteString fullList

-- TODO ### inefficient ahem
splitListAt :: [a] -> (a -> Bool) -> [a] -> [[a]] -> [[a]]
splitListAt [] _ currentList lists = lists++[currentList]
splitListAt (x:xs) f currentList lists | f x == True = splitListAt xs f [] (lists++[currentList])
                                       | otherwise   = splitListAt xs f (currentList ++ [x]) lists

getNameList :: Get NameList
getNameList = do
    len <- getWord32
    list <- replicateM (fromEnum len) getWord8
    return $ NameList $ map B.pack (splitListAt (map (toEnum . fromEnum) list) (== ',') [] [])

instance Binary NameList where
    put = putNameList
    get = getNameList

getMPInt :: Get Integer
getMPInt = do
    len <- getWord32
    bytes <- replicateM (fromEnum len) getWord8
    return $ reconstructInteger bytes 0
    where
        reconstructInteger :: [Word8] -> Integer -> Integer -- TODO if < 0
        reconstructInteger [] i     = i
        reconstructInteger (x:xs) i = reconstructInteger xs $ (i `shiftL` 8) .|. (fromIntegral x)

putMPInt :: Integer -> Put
putMPInt i | i < 0  = error "OEPS NOT IMPLEMENTED: putMPInt i < 0"
           | i == 0 = putWord32 0
putMPInt i = do
    let rawList = makeOk $ reverse $ deconstructInteger i []
    putWord32 $ toEnum $ fromEnum $ length rawList
    forM_ rawList put
    where
        deconstructInteger :: Integer -> [Word8] -> [Word8]
        deconstructInteger i x | i /= 0  = deconstructInteger (i `shiftR` 8) $ (fromIntegral $ i .&. 0xff):x
                               | i == 0  = x
        makeOk rawList | testBit (head rawList) 7 == True = 0:rawList -- head won't fail since i > 0
                       | otherwise                        = rawList

getString :: Get SshString
getString = do
    len <- getWord32
    bytes <- replicateM (fromEnum len) getWord8
    return $ B.pack $ map (toEnum . fromEnum) bytes

putString :: SshString -> Put
putString s = do
    let bytes = (map (toEnum . fromEnum) $ B.unpack s) :: [Word8]
    putWord32 $ toEnum $ fromEnum $ length bytes
    forM_ bytes put

data Packet =
    Disconnect { -- 1
      disc_code :: Int
    , disc_description :: String
    , disc_language :: String
    }
   | ServiceRequest { -- 5
      serviceReqName :: SshString
   }
   | ServiceAccept { -- 6
      serviceAccName :: SshString
   }
   | KEXInit { -- 20
       rawPacket :: SshString -- Because we have to use it in hashes
    ,  kexCookie :: [Word8] -- 16 bytes
      -- Possible algos
    , kex_algos :: [KEXAlgorithm]
    , host_key_algos :: [HostKeyAlgorithm]
    , enc_c2s :: [CryptionAlgorithm]
    , enc_s2c :: [CryptionAlgorithm]
    , mac_c2s :: [HashMac]
    , mac_s2c :: [HashMac]
    --, compression
    --, languages
    }
  | NewKeys -- 21
  | KEXDHInit { -- 30
      dh_e :: Integer
    }
  | KEXDHReply { -- 31
      dh_hostKeyAndCerts :: SshString -- K_S
    , dh_f :: Integer
    , dh_H_signature :: SshString
    }
    deriving Show

putPacket :: Packet -> Put
putPacket (ServiceRequest n) = do
    put (5 :: Word8)
    putString n
putPacket (KEXInit _ c ka hka ecs esc mcs msc) = do
    put (20 :: Word8) -- KEXInit
    forM c put -- Cookie, 16 bytes
    put $ NameList { names = (map kexName ka) }
    put $ NameList { names = (map hostKeyAlgorithmName hka) }
    put $ NameList { names = (map cryptoName esc) }
    put $ NameList { names = (map cryptoName ecs) }
    put $ NameList { names = (map hashName mcs) }
    put $ NameList { names = (map hashName msc) }
    put $ NameList { names = [B.pack "none"] } -- compression
    put $ NameList { names = [B.pack "none"] } -- compression
    put $ NameList { names = [] }
    put $ NameList { names = [] }
    put $ (0 :: Word8) -- firstKexFollows
    putWord32 0 -- Future Use
putPacket NewKeys = put (21 :: Word8)
putPacket (KEXDHInit e) = do
    put (30 :: Word8)
    putMPInt e

-- When reading a namelist, we handily drop all the entries that we don't know about. Order in the server list is irrelevant, client's first is chosen
parseServerNameListFiltered :: (a -> SshString) -> [a] -> NameList -> [a]
parseServerNameListFiltered getName clientList serverList = filter ((`elem` (names serverList)) . getName) clientList

getPacket :: Get Packet
getPacket = do
    msg <- getWord8
    case msg of
        1  -> do -- Disconnect
            r <- fromEnum `liftM` getWord32
            desc <- B.unpack `liftM` getString
            lang <- B.unpack `liftM` getString
            return $ Disconnect r desc lang
        6  -> do -- ServiceAccept
            s <- getString
            return $ ServiceAccept s
        20 -> do -- KEXInit
            c <- replicateM 16 getWord8
            ka <- parseServerNameListFiltered kexName clientKEXAlgos `liftM` get
            hka <- parseServerNameListFiltered hostKeyAlgorithmName clientHostKeys `liftM` get
            ecs <- parseServerNameListFiltered cryptoName clientCryptos `liftM` get
            esc <- parseServerNameListFiltered cryptoName clientCryptos `liftM` get
            mcs <- parseServerNameListFiltered hashName clientHashMacs `liftM` get
            msc <- parseServerNameListFiltered hashName clientHashMacs `liftM` get
            return $ KEXInit B.empty c ka hka ecs esc mcs msc
        21 -> return NewKeys
        31 -> do -- KEXDHReply
            k_S <- getString
            f <- getMPInt
            h_sig <- getString
            return $ KEXDHReply k_S f h_sig
        _ -> error $ "unhandled getPacket, msg was " ++ show msg

instance Binary Packet where
    put = putPacket
    get = getPacket

type ClientPacket = Packet
type ServerPacket = Packet

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

getServerVersionString :: Socket -> IO String
getServerVersionString s = do l <- sockReadLine s
                              if B.pack "SSH-2.0" `B.isPrefixOf` l
                                then return . B.unpack $ l
                                else getServerVersionString s

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

processPacket :: ServerPacket -> IO ()
processPacket p = putStrLn $ "processPacket:" ++ show p

annotatePacketWithPayload :: ServerPacket -> SshString -> ServerPacket 
annotatePacketWithPayload packet@(KEXInit _ _ _ _ _ _ _ _) pl = packet { rawPacket = pl }
annotatePacketWithPayload p _ = p

sGetPacket :: Socket -> SshTransport -> IO ServerPacket
sGetPacket s t = do
    (packlen, padlen) <- getSizes s t
    putStrLn $ show (packlen, padlen)
    payload <- sockReadBytes s (packlen - padlen - 1) -- TODO decode as block
    padding <- sockReadBytes s padlen
    -- TODO verify MAC
    let packet = (decode payload) :: ServerPacket
    return $ annotatePacketWithPayload packet payload

makeWord8 x = map (toEnum . fromEnum) $ B.unpack x

createKeyData :: SshString -> SshString -> Char -> SshString -> [Word8]
createKeyData sharedSecret exchangeHash typeChar sId =
    makeWord8 $ createKeyData' {-sha1-} (B.concat [sharedSecret, exchangeHash]) (B.concat [B.pack [typeChar], sId])

createKeyData' :: SshString -> SshString -> SshString -- make sha1 configurable ### TODO
createKeyData' init append = B.concat [hashed, createKeyData' init hashed]
  where hashed = bytestringDigest $ sha1 $ B.concat [init, append]

--computeEncryptionInfo :: HashFunction -> String -> String

data DHGroup = DHGroup {
      safePrime :: Integer
    , generator :: Integer
    -- , orderOfSubgroup :: Integer TODO: FIND THIS ONE OUT!
} deriving Show

-- TODO: use group 14!
dhGroup1 = DHGroup 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF 2

data ConnectionData = ConnectionData {
      sessionId :: [Word8]
    , sharedSecret :: [Word8]
    , exchangeHash :: [Word8]
    , client2ServerIV :: [Word8]
    , server2ClientIV :: [Word8]
    , client2ServerEncKey :: [Word8]
    , server2ClientEncKey :: [Word8]
    , client2ServerIntKey :: [Word8]
    , server2ClientIntKey :: [Word8]
}

dhComputeExchangeHash :: SshString -> SshString -> SshString -> SshString -> SshString -> Integer -> Integer -> SshString -> SshString
dhComputeExchangeHash clientIdent serverIdent clientKexPayload serverKexPayload hostKey e f sharedSecret =
  bytestringDigest $ sha1 $ runPut $ do -- TODO make sha1 configurable
    put clientIdent
    put serverIdent
    put clientKexPayload
    put serverKexPayload
    put hostKey
    putMPInt e
    putMPInt f
    put sharedSecret

dhComputeSharedSecret :: Integer -> Integer -> Integer -> SshString
dhComputeSharedSecret f x p = runPut $ putMPInt $ modexp f x p


filterNewlines :: SshString -> SshString
filterNewlines s = B.filter (not . (\x -> x == '\n' || x == '\r')) s -- Filter only the FINAL \r\n??? ###

--TODO use hash
diffieHellmanGroup :: DHGroup -> Packet -> Packet -> SshTransport -> Socket -> IO ConnectionData
diffieHellmanGroup (DHGroup p g) clientKexInit serverKexInit t s = do
    let q = (p - 1) `div` 2 -- let's *assume* this is the order of the subgroup?
    x <- randIntegerOneToNMinusOne q
    let e = modexp g x p
        dhInit = KEXDHInit e
    putStrLn $ show dhInit
    sendAll s $ makeSshPacket t $ runPut $ put dhInit
    dhReply <- sGetPacket s t
    putStrLn $ show dhReply
    newKeys <- sGetPacket s t
    putStrLn $ show newKeys

    let sharedSecret = dhComputeSharedSecret (dh_f dhReply) x p
        cvs = filterNewlines $ B.pack clientVersionString
        serverVersion = B.pack "OpenSSH_5.1p1 Debian-5" -- ### TODO
        svs = filterNewlines serverVersion
        hostKey = dh_hostKeyAndCerts dhReply -- AND certs? ###
        exchangeHash = dhComputeExchangeHash {-hash-} cvs svs (rawPacket clientKexInit) (rawPacket serverKexInit) hostKey e (dh_f dhReply) sharedSecret
        sId = undefined --
        theMap = \c -> createKeyData sharedSecret exchangeHash c sId
        [c2sIV, s2cIV, c2sEncKey, s2cEncKey, c2sIntKey, s2cIntKey] = map theMap ['A' .. 'F']
        cd = ConnectionData sId (makeWord8 sharedSecret) (makeWord8 exchangeHash) c2sIV s2cIV c2sEncKey s2cEncKey c2sIntKey s2cIntKey
    putStrLn "A"
    putStrLn $ show hostKey
    putStrLn "B"
    putStrLn $ show exchangeHash
    case newKeys of
        NewKeys -> return cd
        _       -> error "Expected NEWKEYS"

dhGroup1KEXAlgo = KEXAlgorithm (B.pack "diffie-hellman-group1-sha1") (diffieHellmanGroup dhGroup1 {-sha1-})
clientKEXAlgos = [dhGroup1KEXAlgo]

doKex :: Socket -> IO ConnectionData
doKex s = do
    --cookie <- fmap (fromInteger . toInteger) $ replicateM 16 $ (randomRIO (0, 255 :: Int)) :: IO [Word8]
    let cookie = replicate 16 (-1 :: Word8) -- TODO random
    let clientKex = KEXInit B.empty cookie clientKEXAlgos clientHostKeys clientCryptos clientCryptos clientHashMacs clientHashMacs
    let initialTransport = SshTransport noCrypto noHashMac
    sendAll s $ makeSshPacket initialTransport $ runPut $ put clientKex
    serverKex <- sGetPacket s initialTransport
    putStrLn $ show serverKex
    -- assert KEXInit packet
    let kexFn = head $ kex_algos serverKex
    connectiondata <- handleKex kexFn clientKex serverKex initialTransport s
    sendAll s $ makeSshPacket initialTransport $ runPut $ put NewKeys
    sendAll s $ makeSshPacket initialTransport $ runPut $ put $ ServiceRequest $ B.pack "ssh-wololooo"
    putStrLn "KEX DONE?"
    return connectiondata

clientLoop :: Socket -> SshTransport -> IO ()
clientLoop = error "clientloop"

main :: IO ()
main = do
    connection <- connect' "localhost" 22
    --hSetBuffering connection $ BlockBuffering Nothing
    serverVersion <- getServerVersionString connection
    debug serverVersion
    sendAll connection $ B.pack clientVersionString
    cd <- doKex connection
    --requestService (B.pack "ssh-userauth")
    clientLoop connection undefined
    sClose connection
    where
      -- Higher-level connect function
      connect' hostname port = do
        protocol <- getProtocolNumber "tcp"
        entry <- getHostByName hostname
        sock <- socket (hostFamily entry) Stream protocol
        connect sock $ SockAddrInet (fromIntegral port) $ hostAddress entry
        return sock
