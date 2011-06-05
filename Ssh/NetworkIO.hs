module Ssh.NetworkIO (
      NameList(..)
    , sockReadLine
    , sockReadBytes
    , encodeAsWord32
    , encodeAsWord8
    , putRawByteString
    , getWord32
    , putWord32
    , putNameList
    , getNameList
    , putMPInt
    , getMPInt
    , getString
    , putString
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


type SshString = B.ByteString


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


encodeAsWord32 i = fromInteger $ toInteger i :: Word32
encodeAsWord8 i = fromInteger $ toInteger i :: Word8

putRawByteString b = forM_ (map (fromInteger . toInteger . ord) $ B.unpack b) (put :: Word8 -> Put)

getWord32 = getWord32be
putWord32 = putWord32be

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
