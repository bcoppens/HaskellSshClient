{-# LANGUAGE OverloadedStrings,CPP #-}

-- | Cryptographic functionality for SSH. Define common encryption and decryption modes
--   You can compile this with 2 modes: -DNOPURE, which uses unsafely performed OpenSSL bindings because they are faster.
--   The other mode (default) uses the pure Codec.Encryption.AES from the Crypto package.
module Ssh.Cryption (
      CryptionAlgorithm (..)
    , CryptionState (..)
    , CryptionInfo (..)
    , CryptoFunction
    -- * CBC Mode
    , cbcAesEncrypt
    , cbcAesDecrypt
    -- * SDCTR Mode
    , ctrAesEncrypt
    , ctrAesDecrypt
    -- * Miscelaneous
    , noCrypto
    -- TODO: these in a seperate file?
    , padToInWord8
    , toBigEndian
    , padTo
    , asBigEndian
)

where

import Data.Word
import Data.Bits
import qualified Data.ByteString.Lazy as B

import Codec.Utils
import Data.LargeWord
import Data.List.Split
import qualified Data.DList as DList
import Control.Monad
import Control.Monad.State

#ifdef NOPURE
import qualified OpenSSL.Cipher as OpenSSL
import qualified Data.ByteString as BS
import System.IO.Unsafe
#else
import qualified Codec.Encryption.AES as AES
#endif

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


instance Show CryptionAlgorithm where
    show = show . cryptoName

-- | No crypto, to set up the initial KEX exchange
noCrypto = CryptionAlgorithm "none" noop noop 0

noop :: CryptoFunction
noop _ t = return t

-- | Converts the 'Integer to a '[Word8]' (base 256) list, which has the required 'Int length
padToInWord8 :: Integral a => Int -> a -> [Word8]
padToInWord8 = i2osp

---------
-- CBC --
---------

-- | Decrypt with AES with the specified key length in CBC mode
cbcAesDecrypt :: Int -> CryptoFunction
cbcAesDecrypt ks key enc = do
    -- Decode in chunks of 128 bits
    let chunks = splitEvery 16 enc
    DList.toList `liftM` cbcDecryptLoop (aesDecrypt ks) key chunks DList.empty

-- | Encrypt with AES with the specified key length in CBC mode
cbcAesEncrypt :: Int -> CryptoFunction
cbcAesEncrypt ks key dec = do
    -- Encrypt in chunks of 128 bits
    let chunks = splitEvery 16 dec
    DList.toList `liftM` cbcEncryptLoop (aesEncrypt ks) key chunks DList.empty

-- | Generic decrypt with CBC. Takes a decryption function, a key, a ciphertext (split into chunks of the right blocksize) and updates the CryptionState accordingly.
cbcDecryptLoop :: ([Word8] -> [Word8] -> [Word8]) -> [Word8] -> [[Word8]] -> DList.DList Word8 -> CryptionState (DList.DList Word8)
cbcDecryptLoop _ _ [] acc = return acc
cbcDecryptLoop decryptionFunction key (enc:encs) acc = do
    state <- stateVector `liftM` get
    let dec   = decryptionFunction key enc
        plain = cbcDec dec state
    put $ CryptionInfo enc

    -- Accumulate using a DList. This is a lot faster than just keeping on concatenating [Word8]s :-) (TODO: use blaze-builder?)
    cbcDecryptLoop decryptionFunction key encs $ DList.append acc $ DList.fromList plain

-- | Generic encryption with CBC. Takes an encryption function, a key, the plaintext (split into chunks of the right blocksize), and updates the CryptionState accordingly
cbcEncryptLoop :: ([Word8] -> [Word8] -> [Word8]) -> [Word8] -> [[Word8]] -> DList.DList Word8 -> CryptionState (DList.DList Word8)
cbcEncryptLoop _ _ [] acc = return acc
cbcEncryptLoop encryptionFunction key (dec:decs) acc = do
    state <- stateVector `liftM` get
    let toEnc = cbcEnc dec state
        enc   = encryptionFunction key toEnc
    put $ CryptionInfo enc

    -- Accumulate using a DList. This is a lot faster than just keeping on concatenating [Word8]s :-) (TODO: use blaze-builder?)
    cbcEncryptLoop encryptionFunction key decs $ DList.append acc $ DList.fromList enc

-- | Decode with CBC
cbcDec :: [Word8] -> [Word8] -> [Word8]
cbcDec x y = map (uncurry xor) $ zip x y

-- | Encode with CBC
cbcEnc = cbcDec

---------
-- CTR --
---------

-- | Decrypt with AES with the specified key length in Stateful-Decryption Counter Mode (see RFC 4344, pp4-5)
ctrAesDecrypt :: Int -> CryptoFunction
ctrAesDecrypt ks key enc = do
    -- Decode in chunks of 128 bits
    let chunks = splitEvery 16 enc
    DList.toList `liftM` ctrDecryptLoop (aesEncrypt ks) 128 key chunks DList.empty

-- | Encrypt with AES with the specified key length in CBC mode
ctrAesEncrypt :: Int -> CryptoFunction
ctrAesEncrypt ks key dec = do
    -- Encrypt in chunks of 128 bits
    let chunks = splitEvery 16 dec
    DList.toList `liftM` ctrEncryptLoop (aesEncrypt ks) 128 key chunks DList.empty

-- | Read a list of characters big endian as a big endian integer
asBigEndian :: [Word8] -> Integer
asBigEndian x = asBigEndian' x 0
    where
        asBigEndian' [] acc     = acc
        asBigEndian' (x:xs) acc = asBigEndian' xs $ 256*acc + (toEnum $ fromEnum x)

-- TODO make this all more efficient!

-- | Convert an Integer into a big endian list of characters
toBigEndian :: Integer -> [Word8]
toBigEndian x = reverse $ toBigEndian' x
    where
        toBigEndian' :: Integer -> [Word8]
        toBigEndian' 0 = []
        toBigEndian' x = [toEnum $ fromEnum r] ++ toBigEndian' d
            where (d,r) = x `quotRem` 256

-- | Pad to a length to the left
padTo :: Int -> Word8 -> [Word8] -> [Word8]
padTo to with l = (replicate (to - length l) with) ++ l


-- | Generic decrypt with CTR. Like 'cbcDecryptLoop', also takes block size in bits
ctrDecryptLoop :: ([Word8] -> [Word8] -> [Word8]) -> Int -> [Word8] -> [[Word8]] -> DList.DList Word8 -> CryptionState (DList.DList Word8)
ctrDecryptLoop _ _ _ [] acc = return acc
ctrDecryptLoop encryptionFunction bs key (enc:encs) acc = do
    -- Get our 128bit IV
    state <- (take 16 . stateVector) `liftM` get
    let -- Encrypt our state
        xEnc = encryptionFunction key state

        -- Get the plaintext by XORing the encrypted X with the ciphertext
        plain = cbcDec xEnc enc

        -- Interpret the IV as an unsigned network-byte order integer (big endian)
        x     = asBigEndian state

        -- Next state is x+1 stored as unsigned network-byte order integer (modulo 2^blocksize)
        x'    = padTo (bs `div` 8) 0 $ toBigEndian $ (x+1) `mod` 2^bs

    put $ CryptionInfo x'

    -- Accumulate using a DList. This is a lot faster than just keeping on concatenating [Word8]s :-) (TODO: use blaze-builder?)
    ctrDecryptLoop encryptionFunction bs key encs $ DList.append acc $ DList.fromList plain

-- | Generic encryption with CBC. Like 'cbcEncryptLoop', and it also takes a block size in bits
ctrEncryptLoop = ctrDecryptLoop

-------------------------------------
-- Encryption/Decryption functions --
-------------------------------------

-- Function signatures

-- | Encrypt with AES: keysize, key (keysize bits), plaintext (128 bits)
aesEncrypt :: Int -> [Word8] -> [Word8] -> [Word8]

-- | Decrypt: keysize, key (keysize bits), ciphertext (128 bits)
aesDecrypt :: Int -> [Word8] -> [Word8] -> [Word8]

#ifdef NOPURE

zeroIV = BS.pack $ [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] -- ^ 16 0 bytes

-- We don't let OpenSSL do the CBC/CTR mode, we'll do it ourselves, so we create a new context every time. I do this because this lets me change
-- everything rather localizedly...
-- This means we don't need to care about the unsafe side effect that the context is destructively updated, since we don't re-use it.
-- This also means that we have to chose CBC, and let it XOR (CBC) with a 0 IV...
aesEncrypt 256 key plain = BS.unpack $ unsafePerformIO $ do
    ctx <- OpenSSL.newAESCtx OpenSSL.Encrypt (BS.pack $ take 32 key) zeroIV
    OpenSSL.aesCBC ctx $ BS.pack plain

-- Same remarks as above
aesDecrypt 256 key enc = BS.unpack $ unsafePerformIO $ do
    ctx <- OpenSSL.newAESCtx OpenSSL.Decrypt (BS.pack $ take 32 key) zeroIV
    OpenSSL.aesCBC ctx $ BS.pack enc

#else

-- DAMN THIS IS FUGLY!!!! ### TODO FIXME
convertString1 = fromInteger . fromOctets 256
convertString = fromInteger . fromOctets 256


aesEncrypt 256 key plain =
    padToInWord8 16 $ AES.encrypt (convertString1 (take 32 key) :: Word256) (convertString plain :: Word128)


aesDecrypt 256 key enc =
    let k =  {-# SCC "Take32Key" #-} (take 32 key)
        ke = {-# SCC "convertKey" #-} (convertString1 k :: Word256)
        e = {-# SCC "convertEnc" #-} (convertString enc :: Word128)
        dec = {-# SCC "doDecrypt" #-} AES.decrypt ke e
    in padToInWord8 16 $ dec

#endif
