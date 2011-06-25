module Main where

import Test.Framework (defaultMain, testGroup)

import qualified Ssh.NetworkIO.Tests
import qualified Ssh.Cryption.Tests

main :: IO ()
main = defaultMain
    [
        testGroup "Ssh.NetworkIO.Tests" Ssh.NetworkIO.Tests.tests
      , testGroup "Ssh.Cryption.Tests" Ssh.Cryption.Tests.tests
    ]