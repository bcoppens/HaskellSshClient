{-# LANGUAGE OverloadedStrings #-}

module Ssh.Cryption (
      CryptionAlgorithm (..)
    , CryptionState (..)
    , CryptionInfo (..)
    , CryptoFunction
    , aesEncrypt
    , cbcAesDecrypt
    , noCrypto
)

where

import Data.Word
import Data.Bits
import qualified Data.ByteString.Lazy as B

import qualified Codec.Encryption.AES as AES
import Codec.Utils
import Data.LargeWord
import Control.Monad.State

type SshString = B.ByteString

data CryptionInfo = CryptionInfo {
    stateVector :: [Word8]
}

type CryptionState = State CryptionInfo

type CryptoFunction = [Word8] -> [Word8] -> CryptionState [Word8]

data CryptionAlgorithm = CryptionAlgorithm {
      cryptoName :: SshString
    , encrypt :: CryptoFunction -- encrypt: key -> plaintext -> result
    , decrypt :: CryptoFunction -- encrypt: key -> ciphertext -> result
    , blockSize :: Int -- can be 0 for stream ciphers
}

cbcAesDecrypt :: Int -> CryptoFunction
cbcAesDecrypt ks key enc = do
    state <- stateVector `liftM` get
    let plain = aesDecrypt ks key enc
    put $ CryptionInfo plain
    return plain

instance Show CryptionAlgorithm where
    show = show . cryptoName

noCrypto = CryptionAlgorithm "none" noop noop 0 -- for the initial KEX

noop :: CryptoFunction
noop _ t = return t

cbcDec :: [Word8] -> [Word8] -> [Word8]
cbcDec x y = map (uncurry xor) $ zip x y

cbcEnc = cbcDec

-- DAMN THIS IS FUGLY!!!! ### TODO FIXME
convertString1 = fromInteger . fromOctets 256
convertString = fromInteger . fromOctets 256
--reconvertString s = B.pack $ map (toEnum . fromEnum) $ toOctets 256 s
reconvertString s = toOctets 256 s

aesEncrypt :: Int -> [Word8] -> [Word8] -> [Word8]
aesEncrypt 256 key plain =
    reconvertString $ AES.encrypt (convertString1 key :: Word256) (convertString plain :: Word128)

aesDecrypt :: Int -> [Word8] -> [Word8] -> [Word8]
aesDecrypt 256 key enc =
    reconvertString $ AES.decrypt (convertString1 key :: Word256) (convertString enc :: Word128)

