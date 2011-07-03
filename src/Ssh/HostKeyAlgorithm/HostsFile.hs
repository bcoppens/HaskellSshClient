-- | A simple verifier for a host key: check the hosts key file. If the key doesn't match, abort; if the key doesn't exist: ask the user
module Ssh.HostKeyAlgorithm.HostsFile (
    checkHostKeyInFile
) where

import Data.Char
import qualified Data.ByteString.Lazy as B

import Ssh.Debug
import Ssh.String
import Ssh.PublicKeyAlgorithm

-- TODO: actually do the file stuff

checkHostKeyInFile :: PublicKeyAlgorithm -> SshString -> SshString -> IO Bool
checkHostKeyInFile algo hostName pubKey = do
    let fp  = unpackToString $ fingerprint algo pubKey
        str = "The fingerprint for server " ++ (unpackToString hostName) ++ " is " ++ fp ++ ". Accept? y/n"

    -- For the moment, just ask the user if he accepts this key
    readUntilAcceptOrReject str
    where
        readUntilAcceptOrReject str = do
            putStrLn str
            l <- getLine
            case map toLower l of
                "y"       -> return True
                "n"       -> return False
                otherwise -> readUntilAcceptOrReject str
