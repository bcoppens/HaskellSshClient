module Ssh.Cryption (
      CryptionAlgorithm (..)
    , aesEncrypt
    , aesDecrypt
    , noCrypto
)

where

import Data.Word
import Data.Bits
import qualified Data.ByteString.Lazy.Char8 as B

import qualified Codec.Encryption.AES as AES
import Codec.Utils
import Data.LargeWord

type SshString = B.ByteString

data CryptionAlgorithm = CryptionAlgorithm {
      cryptoName :: SshString
    , encrypt :: [Word8] -> [Word8] -> [Word8] -- encrypt: key -> plaintext -> result
    , decrypt :: [Word8] -> [Word8] -> [Word8] -- encrypt: key -> ciphertext -> result
    , blockSize :: Int -- can be 0 for stream ciphers
}

instance Show CryptionAlgorithm where
    show = B.unpack . cryptoName

noCrypto = CryptionAlgorithm (B.pack "none") (\_ -> id) (\_ -> id) 0 -- for the initial KEX

cbcDec :: [Word8] -> [Word8] -> [Word8]
cbcDec x y = map (uncurry xor) $ zip x y

cbcEnc = cbcDec

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

decryptBytes :: [Word8] -> [Word8] -> SshConnection [Word8]
decryptBytes key s = do
    transport <- MS.get
    let s2c = server2client transport
        v = serverVector transport
        crypt = decrypt $ crypto s2c
        decrypted = crypt key s
    MS.put $ transport { serverVector = s }
    return $ cbcDec v decrypted
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
