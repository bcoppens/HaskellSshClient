{-# LANGUAGE OverloadedStrings #-}

import Network
import Data.Binary.Put
import Data.Word
import Control.Monad
import qualified Control.Monad.State as MS
import Data.List
import Data.Maybe
import qualified Data.ByteString.Lazy as B

import Network.BSD ( HostEntry (..), getProtocolNumber, getHostByName
                   , hostAddress
                   )
import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import Network.Socket.ByteString.Lazy

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers

import Debug.Trace

import Ssh.NetworkIO
import Ssh.Packet
import Ssh.KeyExchange
import Ssh.Cryption
import Ssh.ConnectionData
import Ssh.KeyExchangeAlgorithm
import Ssh.KeyExchangeAlgorithm.DiffieHellman
import Ssh.KeyExchange
import Ssh.HashMac
import Ssh.HostKeyAlgorithm
import Ssh.Transport

import Debug.Trace
debug = putStrLn

type SshString = B.ByteString

clientVersionString = "SSH-2.0-BartSSHaskell-0.0.1 This is crappy software!\r\n"

chunkUpString :: Int -> SshString -> [[Word8]] -- bytesPerChunk string
chunkUpString bpc s = chunkIt bytes []
    where bytes = map (toEnum . fromEnum) $ B.unpack s
          chunkIt :: [Word8] -> [[Word8]] -> [[Word8]]
          chunkIt b acc | todo == []  = new
                        | otherwise   = chunkIt todo new
                        where (chunk, todo)   = splitAt bpc b
                              new             = acc ++ [chunk] -- TODO

--clientCryptos = [ (CryptionAlgorithm "aes256-cbc" (aesEncrypt 256) (aesDecrypt 256) 128) ]
clientCryptos = [ (CryptionAlgorithm "aes256-cbc" (error "Later...") (error "Later...") 128) ]

clientHashMacs = [ HashMac "hmac-sha1" (error "OEPS") 0 ]

rsaHostKey = HostKeyAlgorithm "ssh-rsa"
clientHostKeys = [rsaHostKey]

dhGroup1KEXAlgo = KeyExchangeAlgorithm "diffie-hellman-group1-sha1" (diffieHellmanGroup dhGroup1 {-sha1-})
clientKEXAlgos = [dhGroup1KEXAlgo]

getServerVersionString :: Socket -> IO SshString
getServerVersionString s = do l <- sockReadLine s
                              if "SSH-2.0" `B.isPrefixOf` l
                                then return l
                                else getServerVersionString s

processPacket :: ServerPacket -> IO ()
processPacket p = putStrLn $ "processPacket:" ++ show p

--computeEncryptionInfo :: HashFunction -> String -> String

clientLoop :: Socket -> SshTransport -> IO ()
clientLoop = error "clientloop"


main :: IO ()
main = do
    connection <- connect' "localhost" 22
    --hSetBuffering connection $ BlockBuffering Nothing
    serverVersion <- getServerVersionString connection
    debug $ show serverVersion
    sendAll connection clientVersionString
    -- TODO remove runState!
    let tinfo = SshTransportInfo undefined (error "Client2ServerTransport") [] 0 (error "Server2ClientTransport") [] 0 (error "ConnectionData")
    cd <- MS.evalStateT (doKex clientVersionString clientKEXAlgos clientHostKeys clientCryptos clientCryptos clientHashMacs clientHashMacs connection sGetPacket) tinfo
    --requestService (B.pack "ssh-userauth")
    clientLoop connection undefined
    sClose connection
    where
      -- Higher-level connect function
      connect' hostname port = do
        protocol <- getProtocolNumber "tcp"
        entry <- getHostByName hostname
        sock <- socket (hostFamily entry) Stream protocol
        connect sock $ SockAddrInet (fromIntegral port) $ hostAddress entry
        return sock
