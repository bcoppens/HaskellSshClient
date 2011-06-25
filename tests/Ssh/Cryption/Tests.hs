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

aesCbcEncryptThenDecrypt ks plain key iv =
    let encrypted = evalState (cbcAesEncrypt ks key plain) $ CryptionInfo iv
        decrypted = evalState (cbcAesDecrypt ks key encrypted) $ CryptionInfo iv
    in  (length key >= 16 && length iv >= 16) ==> encrypted == decrypted

aesEncryptThenDecrypt = map (\ks -> testProperty ("AES " ++ show ks ++ " CBC Encrypt then Decrypt") $ aesCbcEncryptThenDecrypt ks) [ 256 ]

tests :: [Test]
tests = concat
    [
        aesEncryptThenDecrypt
    ]

