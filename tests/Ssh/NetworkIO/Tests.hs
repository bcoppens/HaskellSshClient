module Ssh.NetworkIO.Tests (
    tests
) where

import Test.Framework
import qualified Test.HUnit as H
import Test.Framework.Providers.HUnit

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

import qualified Data.ByteString.Lazy as B

import Debug.Trace

import Ssh.NetworkIO

type SshString = B.ByteString

loadString s = B.pack $ map (toEnum . fromEnum) s

checkPut :: (Enum a, Eq b) => ([a], b) -> (b -> Put) -> H.Assertion -- Int instead of Word8...
checkPut (bytes,actualValue) putter = do
    let value      = runPut $ putter actualValue
        cmp        = loadString bytes
        result     = value == cmp
        --result'    = trace ( "Put: " ++ show result ++ ": Computed: " ++ (show $ B.unpack value) ++ " =?= Should be: " ++ (show $ B.unpack cmp)) result
        result' = result
    H.assert $ result'

checkGet :: (Enum a, Eq b) => ([a], b) -> Get b -> H.Assertion -- Int instead of Word8...
checkGet (bytes,actualValue) getter = do
    let value   = runGet getter $ loadString bytes
        result  = value == actualValue
        --result' = trace ( "Get: " ++ show result ++ ": Computed: " ++ (show value) ++ " =?= Should be: " ++ (show mpint)) result
        result' = result
    H.assert $ result'

mpIntTestValues =
    [
      ([0, 0, 0, 0], 0)
    , ([0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7], 0x9a378f9b2e332a7)
    , ([0, 0, 0, 2, 0, 0x80], 0x80)
    , ([0, 0, 0, 2, 0xed, 0xcc], -0x1234)
    , ([0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41, 0x11], -0xdeadbeef)
    ]

boolPutTestValues =
    [
      ([0], False)
    , ([1], True)
    ]

boolGetTestValues = ([2], True) : boolPutTestValues -- 2 should be read into True, but True must not be written back as 2!

genericGetCheck name getter values = map (\t@(_, v) -> testCase ("Get " ++ name ++ ": " ++ show v) $ checkGet t getter) values
genericPutCheck name putter values = map (\t@(_, v) -> testCase ("Put " ++ name ++ ": " ++ show v) $ checkPut t putter) values

mpIntGetTests = genericGetCheck "mpInt" getMPInt mpIntTestValues
mpIntPutTests = genericPutCheck "mpInt" putMPInt mpIntTestValues

boolGetTests = genericGetCheck "Bool" getBool boolGetTestValues
boolPutTests = genericPutCheck "Bool" putBool boolPutTestValues

tests :: [Test]
tests = concat
    [
      mpIntGetTests
    , mpIntPutTests
    , boolGetTests
    , boolPutTests
    ]

