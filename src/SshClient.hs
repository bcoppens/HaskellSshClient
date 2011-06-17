{-# LANGUAGE OverloadedStrings #-}

module SshClient (
      main
) where

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
import Ssh.Authentication
import Ssh.Authentication.Password
import Ssh.Debug
import Ssh.Channel
import Ssh.Channel.Session

import Debug.Trace
debug = putStrLn

type SshString = B.ByteString

clientVersionString = "SSH-2.0-BartSSHaskell-0.0.1 This is crappy software!\r\n"

clientCryptos = [ (CryptionAlgorithm "aes256-cbc" (cbcAesEncrypt 256) (cbcAesDecrypt 256) 16) ]

clientHashMacs = [ sha1HashMac ]

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

clientLoop :: Socket -> ConnectionData -> SshConnection ()
clientLoop socket cd = do
    ti <- MS.get
    authOk <- authenticate socket "bartcopp" "ssh-connection" [passwordAuth]
    MS.liftIO $ printDebug $ "Authentication OK? " ++ show authOk
    (channel, newState) <- flip MS.runStateT initialGlobalChannelsState $ openChannel socket sessionHandler ""
    newState' <- flip MS.evalStateT channel $ requestExec socket "cat /home/bartcopp/projecten/haskell/sshclient/README"
    MS.evalStateT loop newState'
        where
            loop = do
                packet <- MS.lift $ sGetPacket socket
                MS.liftIO $ putStrLn $ show packet
                loop

main :: IO ()
main = do
    connection <- connect' "localhost" 22
    --hSetBuffering connection $ BlockBuffering Nothing
    serverVersion <- getServerVersionString connection
    printDebug $ show serverVersion
    sendAll connection clientVersionString
    -- TODO remove runState!
    let tinfo = SshTransportInfo {-(error "HKA")-} (error "Client2ServerTransport") [] 0 (error "Server2ClientTransport") [] 0 (error "ConnectionData")
    (cd, newState) <- MS.runStateT (doKex clientVersionString serverVersion clientKEXAlgos clientHostKeys clientCryptos clientCryptos clientHashMacs clientHashMacs connection sGetPacket) tinfo
    MS.runStateT (clientLoop connection cd) newState
    sClose connection
    where
      -- Higher-level connect function
      connect' hostname port = do
        protocol <- getProtocolNumber "tcp"
        entry <- getHostByName hostname
        sock <- socket (hostFamily entry) Stream protocol
        connect sock $ SockAddrInet (fromIntegral port) $ hostAddress entry
        return sock
