module Main where

import Test.Framework (defaultMain, testGroup)

import qualified Ssh.NetworkIO.Tests

main :: IO ()
main = defaultMain
    [
        testGroup "Ssh.NetworkIO.Tests" Ssh.NetworkIO.Tests.tests
    ]