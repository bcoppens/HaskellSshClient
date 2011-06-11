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

checkMPIntPut :: ([Int], Integer) -> H.Assertion -- Int instead of Word8...
checkMPIntPut (bytes,mpint) = do
    let value      = runPut $ putMPInt mpint
        cmp        = loadString bytes
        result     = value == cmp
        --result'    = trace ( "Put: " ++ show result ++ ": Computed: " ++ (show $ B.unpack value) ++ " =?= Should be: " ++ (show $ B.unpack cmp)) result
        result' = result
    H.assert $ result'

checkMPIntGet :: ([Int], Integer) -> H.Assertion -- Int instead of Word8...
checkMPIntGet (bytes,mpint) = do
    let value   = runGet getMPInt $ loadString bytes
        result  = value == mpint
        --result' = trace ( "Get: " ++ show result ++ ": Computed: " ++ (show value) ++ " =?= Should be: " ++ (show mpint)) result
        result' = result
    H.assert $ result'

mpIntTestValues =
    [
      ([0, 0, 0, 0], 0)
    , ([0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7], 0x9a378f9be332a7)
    , ([0, 0, 0, 2, 0, 0x80], 0x80)
    , ([0, 0, 0, 2, 0xed, 0xcc], -0x1234)
    , ([0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41, 0x11], -0xdeadbeef)
    ]

mpIntGetTests  = map (\t@(_, v) -> testCase ("Get mpInt: " ++ show v) $ checkMPIntGet t) mpIntTestValues
mpIntPutTests = map (\t@(_, v) -> testCase ("Put mpInt: " ++ show v) $ checkMPIntPut t) mpIntTestValues

tests :: [Test]
tests = concat
    [
      mpIntGetTests
    , mpIntPutTests
    ]
