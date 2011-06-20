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

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers
import OpenSSL.Random -- random bytes
import qualified Data.ByteString as BS -- Random uses a Strict ByteString

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
import Ssh.String

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
--   We also need a function that can be used to decode and decrypt packets using a given 'Transport'.
--
doKex :: SshString -> SshString -> [KeyExchangeAlgorithm] -> [HostKeyAlgorithm] -> [CryptionAlgorithm] -> [CryptionAlgorithm] -> [HashMac] -> [HashMac] -> SshConnection ConnectionData
doKex clientVersionString serverVersionString clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs = do
    -- Prepare our KEXInit packet

    -- Get 16 bytes of randomness for our cookie.
    -- TODO: use OpenSSL.Random.add for more randomness
    cookie <- MS.liftIO $ BS.unpack `liftM` randBytes 16

    let clientKex = KEXInit B.empty cookie (map kexName clientKEXAlgos) (map hostKeyAlgorithmName clientHostKeys) (map cryptoName clientCryptos) (map cryptoName serverCryptos) (map hashName clientHashMacs) (map hashName serverHashMacs)

    -- Set up the transports
    let initialTransport     = SshTransport noCrypto noHashMac -- TODO this should only be initialized for the *first* Kex, not for rekeying!
        clientKexInitPayload = runPut $ putPacket clientKex
        clientKexPacket      = makeSshPacket initialTransport $ clientKexInitPayload

    -- Initialize the state to be able to send packets
    MS.modify $ \s -> s { client2server = initialTransport, server2client = initialTransport }

    -- Send our KEXInit, wait for their KEXInit
    sPutPacket clientKex
    serverKex <- sGetPacket -- TODO assert this is a KEXInit packet

    printDebugLifted logLowLevelDebug "ServerKEX before filtering:"
    printDebugLifted logLowLevelDebug $ show serverKex

    -- The server's KEXInit probably contains a lot of methods we don't support, throw them away, and get the first KEX method we and the server support
    let filteredServerKex = filterKEXInit clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs serverKex
        kex   = head $ kex_algos filteredServerKex
        kexFn = fromJust $ find (\x -> kexName x == kex) clientKEXAlgos
        serverKexInitPayload = rawPacket serverKex

    printDebugLifted logLowLevelDebug "ServerKEX after filtering:"
    printDebugLifted logLowLevelDebug $ show filteredServerKex

    -- Perform the Key Exchange method supported by both us and the server
    connectiondata <- handleKex kexFn clientVersionString serverVersionString clientKexInitPayload serverKexInitPayload

    -- We have exchanged keys, confirm to the server that the new keys can be put into use. The handleKex already confirmed the server sent theirs!
    sPutPacket NewKeys

    -- Now that the new keys are put into use, set up these keys and the correct encryption, decryption and hashed mac functions in our state to use
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

    printDebugLifted logLowLevelDebug "KEX DONE?"

    return connectiondata
