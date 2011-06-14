{-# LANGUAGE OverloadedStrings #-}

-- | Generic Key Exchange facilities. Performs the key exchange
module Ssh.KeyExchange(
      doKex
) where


import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

import Control.Monad
import qualified Control.Monad.State as MS
import Data.Bits
import Data.Maybe
import Data.List
import qualified Data.ByteString.Lazy as B

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import Network.Socket.ByteString.Lazy

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers

import Data.Digest.Pure.SHA

import Ssh.NetworkIO
import Ssh.Packet
import Ssh.KeyExchangeAlgorithm
import Ssh.ConnectionData
import Ssh.Cryption
import Ssh.Transport
import Ssh.HostKeyAlgorithm
import Ssh.HashMac
import Ssh.Debug

type SshString = B.ByteString

-- | We drop all the entries that we don't know about. Order in the server list is irrelevant, client's first is chosen
serverListFiltered :: [SshString] -> [SshString] -> [SshString]
serverListFiltered clientList serverList = filter (`elem` serverList) clientList

-- | Filter all algorithms from a 'KEXInit' packet that are not in the given arguments.
--   Can be used to see which algorithms are supported by both client and server. Keeps the order of the client's supported lists
filterKEXInit :: [KeyExchangeAlgorithm] -> [HostKeyAlgorithm] -> [CryptionAlgorithm] -> [CryptionAlgorithm] -> [HashMac] -> [HashMac] -> Packet -> Packet
filterKEXInit clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs (KEXInit raw c ka hka ecs esc mcs msc) =
    KEXInit raw c ka' hka' ecs' esc' mcs' msc'
    where
        ka'  = serverListFiltered (map kexName clientKEXAlgos) ka
        hka' = serverListFiltered (map hostKeyAlgorithmName clientHostKeys) hka
        ecs' = serverListFiltered (map cryptoName clientCryptos) ecs
        esc' = serverListFiltered (map cryptoName serverCryptos) esc
        mcs' = serverListFiltered (map hashName clientHashMacs) mcs
        msc' = serverListFiltered (map hashName serverHashMacs) msc

-- | Perform key exchange
--   Needs the version strings of both client and server. Needs a list of all client-side supported algorithms.
--   We also need a socket to perform the key exchange on, and a function that can be used to decode and decrypt packets using a given 'Transport'.
doKex :: SshString -> SshString -> [KeyExchangeAlgorithm] -> [HostKeyAlgorithm] -> [CryptionAlgorithm] -> [CryptionAlgorithm] -> [HashMac] -> [HashMac] -> Socket -> (SshTransport -> Socket -> SshConnection ServerPacket) -> SshConnection ConnectionData
doKex clientVersionString serverVersionString clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs s getPacket = do
    --cookie <- fmap (fromInteger . toInteger) $ replicateM 16 $ (randomRIO (0, 255 :: Int)) :: IO [Word8]
    let cookie = replicate 16 (-1 :: Word8) -- TODO random
    let clientKex = KEXInit B.empty cookie (map kexName clientKEXAlgos) (map hostKeyAlgorithmName clientHostKeys) (map cryptoName clientCryptos) (map cryptoName serverCryptos) (map hashName clientHashMacs) (map hashName serverHashMacs)
    let initialTransport     = SshTransport noCrypto noHashMac
        clientKexInitPayload = runPut $ putPacket clientKex
        clientKexPacket      = makeSshPacket initialTransport $ clientKexInitPayload
    MS.modify $ \s -> s { client2server = initialTransport, server2client = initialTransport }
    sPutPacket initialTransport s clientKex
    serverKex <- getPacket initialTransport s
    printDebugLifted "ServerKEX before filtering:"
    printDebugLifted $ show serverKex
    -- assert KEXInit packet
    let filteredServerKex = filterKEXInit clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs serverKex
        kex   = head $ kex_algos filteredServerKex
        kexFn = fromJust $ find (\x -> kexName x == kex) clientKEXAlgos
        serverKexInitPayload = rawPacket serverKex
    printDebugLifted "ServerKEX after filtering:"
    printDebugLifted $ show filteredServerKex
    connectiondata <- handleKex kexFn clientVersionString serverVersionString clientKexInitPayload serverKexInitPayload (getPacket initialTransport) s
    sPutPacket initialTransport s NewKeys
    let s2c    = head $ enc_s2c filteredServerKex
        s2cfun = fromJust $ find (\x -> cryptoName x == s2c) serverCryptos
        s2cmac = head $ mac_s2c filteredServerKex
        s2cmacfun = fromJust $ find (\x -> hashName x == s2cmac) serverHashMacs
        c2s    = head $ enc_c2s filteredServerKex
        c2sfun = fromJust $ find (\x -> cryptoName x == c2s) serverCryptos
        c2smac = head $ mac_c2s filteredServerKex
        c2smacfun = fromJust $ find (\x -> hashName x == c2smac) serverHashMacs
    MS.modify $ \s -> s { server2client = SshTransport s2cfun s2cmacfun,
                          serverVector = server2ClientIV connectiondata,
                          client2server = SshTransport c2sfun s2cmacfun,
                          clientVector = client2ServerIV connectiondata,
                          connectionData = connectiondata
                         }
    --server2client :: SshTransport
    --, serverVector :: [Word8]
    printDebugLifted "KEX DONE?"
    return connectiondata
