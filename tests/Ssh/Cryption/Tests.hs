{-# LANGUAGE OverloadedStrings #-}

module Ssh.Cryption.Tests (
    tests
) where

import Test.Framework
import Test.QuickCheck
import qualified Test.HUnit as H
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2

import Data.Word
import Control.Monad.State

import qualified Data.ByteString.Lazy as B

import Ssh.Cryption
import Ssh.String
import Ssh.Debug

encryptThenDecryptTest enc dec ks plain key iv =
    let encrypted = evalState (enc ks key plain) $ CryptionInfo iv
        decrypted = evalState (dec ks key encrypted) $ CryptionInfo iv
    in  (length key >= 16 && length iv >= 16 && length plain `mod` 16 == 0) ==> plain == decrypted

encryptThenDecrypt name enc dec keysizes =
    map (\ks -> testProperty (name ++ show ks ++ ": Encrypt then Decrypt == plaintext") $ encryptThenDecryptTest enc dec ks) keysizes

tests :: [Test]
tests = concat
    [
        encryptThenDecrypt "AES CBC" cbcAesEncrypt cbcAesDecrypt [ 256 ]
      , encryptThenDecrypt "AES CTR" ctrAesEncrypt ctrAesDecrypt [ 256 ]
    ]

