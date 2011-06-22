{-# LANGUAGE OverloadedStrings #-}

-- | Cryptographic functionality for SSH. Define common encryption and decryption modes
module Ssh.Cryption (
      CryptionAlgorithm (..)
    , CryptionState (..)
    , CryptionInfo (..)
    , CryptoFunction
    , cbcAesEncrypt
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
import Data.List.Split
import Control.Monad
import Control.Monad.State

import Ssh.Debug
import Ssh.String

-- | State needed for the encryption, such as the IV
data CryptionInfo = CryptionInfo {
    stateVector :: [Word8]
}

-- | Crypto stateful modes like CBC: keep track of the IV
type CryptionState = State CryptionInfo

type CryptoFunction = [Word8] -> [Word8] -> CryptionState [Word8]

data CryptionAlgorithm = CryptionAlgorithm {
      cryptoName :: SshString
    , encrypt :: CryptoFunction -- ^ encrypt: key -> plaintext -> result
    , decrypt :: CryptoFunction -- ^ decrypt: key -> ciphertext -> result
    , blockSize :: Int          -- ^ can be 0 for stream ciphers
}

-- | Decrypt with AES with the specified key length in CBC mode
cbcAesDecrypt :: Int -> CryptoFunction
cbcAesDecrypt ks key enc = do
    -- Decode in chunks of 128 bits
    let chunks = splitEvery 16 enc
    cbcDecryptLoop (aesDecrypt ks) key chunks []

-- | Encrypt with AES with the specified key length in CBC mode
cbcAesEncrypt :: Int -> CryptoFunction
cbcAesEncrypt ks key dec = do
    -- Encrypt in chunks of 128 bits
    let chunks = splitEvery 16 dec
    cbcEncryptLoop (aesEncrypt ks) key chunks []

-- | Generic decrypt with CBC. Takes a decryption function, a key, a ciphertext (split into chunks of the right blocksize) and updates the CryptionState accordingly.
cbcDecryptLoop :: ([Word8] -> [Word8] -> [Word8]) -> [Word8] -> [[Word8]] -> [Word8] -> CryptionState [Word8]
cbcDecryptLoop _ _ [] acc = return acc
cbcDecryptLoop decryptionFunction key (enc:encs) acc = do
    state <- stateVector `liftM` get
    let dec   = decryptionFunction key enc
        plain = cbcDec dec state
    put $ CryptionInfo enc
    cbcDecryptLoop decryptionFunction key encs (acc++plain)

-- | Generic encryption with CBC. Takes an encryption function, a key, the plaintext (split into chunks of the right blocksize), and updates the CryptionState accordingly
cbcEncryptLoop :: ([Word8] -> [Word8] -> [Word8]) -> [Word8] -> [[Word8]] -> [Word8] -> CryptionState [Word8]
cbcEncryptLoop _ _ [] acc = return acc
cbcEncryptLoop encryptionFunction key (dec:decs) acc = do
    state <- stateVector `liftM` get
    let toEnc = cbcEnc dec state
        enc   = encryptionFunction key toEnc
    put $ CryptionInfo enc
    cbcEncryptLoop encryptionFunction key decs (acc++enc)

instance Show CryptionAlgorithm where
    show = show . cryptoName

-- | No crypto, to set up the initial KEX exchange
noCrypto = CryptionAlgorithm "none" noop noop 0

noop :: CryptoFunction
noop _ t = return t

-- | Decode with CBC
cbcDec :: [Word8] -> [Word8] -> [Word8]
cbcDec x y = map (uncurry xor) $ zip x y

-- | Encode with CBC
cbcEnc = cbcDec

-- DAMN THIS IS FUGLY!!!! ### TODO FIXME
convertString1 = fromInteger . fromOctets 256
convertString = fromInteger . fromOctets 256
--reconvertString s = B.pack $ map (toEnum . fromEnum) $ toOctets 256 s
reconvertString s = toOctets 256 s

-- | Encrypt with AES: keysize, key (keysize bits), plaintext (128 bits)
aesEncrypt :: Int -> [Word8] -> [Word8] -> [Word8]
aesEncrypt 256 key plain =
    reconvertString $ AES.encrypt (convertString1 (take 32 key) :: Word256) (convertString plain :: Word128)

-- | Decrypt: keysize, key (keysize bits), ciphertext (128 bits)
aesDecrypt :: Int -> [Word8] -> [Word8] -> [Word8]
aesDecrypt 256 key enc =
    reconvertString $ AES.decrypt (convertString1 (take 32 key) :: Word256) (convertString enc :: Word128)

