{-# LANGUAGE OverloadedStrings #-}

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

type SshString = B.ByteString

-- We drop all the entries that we don't know about. Order in the server list is irrelevant, client's first is chosen
serverListFiltered :: [SshString] -> [SshString] -> [SshString]
serverListFiltered clientList serverList = filter (`elem` serverList) clientList

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

doKex :: SshString -> [KeyExchangeAlgorithm] -> [HostKeyAlgorithm] -> [CryptionAlgorithm] -> [CryptionAlgorithm] -> [HashMac] -> [HashMac] -> Socket -> (SshTransport -> Socket -> IO ServerPacket) -> IO ConnectionData
doKex clientVersionString clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs s getPacket = do
    --cookie <- fmap (fromInteger . toInteger) $ replicateM 16 $ (randomRIO (0, 255 :: Int)) :: IO [Word8]
    let cookie = replicate 16 (-1 :: Word8) -- TODO random
    let clientKex = KEXInit B.empty cookie (map kexName clientKEXAlgos) (map hostKeyAlgorithmName clientHostKeys) (map cryptoName clientCryptos) (map cryptoName serverCryptos) (map hashName clientHashMacs) (map hashName serverHashMacs)
    let initialTransport = SshTransport noCrypto noHashMac
    sendAll s $ makeSshPacket initialTransport $ runPut $ putPacket clientKex -- TODO make configurable
    putStrLn "Mu"
    serverKex <- getPacket initialTransport s
    putStrLn "ServerKEX before filtering:"
    putStrLn $ show serverKex
    -- assert KEXInit packet
    let filteredServerKex = filterKEXInit clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs serverKex
        kex   = head $ kex_algos filteredServerKex
        kexFn = fromJust $ find (\x -> kexName x == kex) clientKEXAlgos
        rawClientKexInit = rawPacket clientKex
        rawServerKexInit = rawPacket serverKex
        makeTransportPacket = makeSshPacket initialTransport
    putStrLn "ServerKEX after filtering:"
    putStrLn $ show filteredServerKex
    connectiondata <- handleKex kexFn clientVersionString rawClientKexInit rawServerKexInit makeTransportPacket (getPacket initialTransport) s
    sendAll s $ makeSshPacket initialTransport $ runPut $ putPacket NewKeys
    sendAll s $ makeSshPacket initialTransport $ runPut $ putPacket (ServiceRequest "ssh-wololooo")
    putStrLn "KEX DONE?"
    return connectiondata
