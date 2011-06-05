{-# LANGUAGE OverloadedStrings #-}

module Ssh.KeyExchange.DiffieHellman (
      diffieHellmanGroup
    , dhGroup1
    , dhKexInitGetHelper
    , dhKexPutPacketHelper
) where

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

import Control.Monad
import qualified Control.Monad.State as MS
import Data.Bits
import qualified Data.ByteString.Lazy.Char8 as B
import qualified Data.ByteString.Char8 as BS

import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import Network.Socket.ByteString.Lazy

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers

import Data.Digest.Pure.SHA

import Ssh.NetworkIO
import Ssh.Packet
import Ssh.KeyExchange
import Ssh.ConnectionData
import Ssh.Cryption
import Ssh.Transport
import Ssh.HostKeyAlgorithm
import Ssh.HashMac

import Debug.Trace

type SshString = B.ByteString

data DHGroup = DHGroup {
      safePrime :: Integer
    , generator :: Integer
    -- , orderOfSubgroup :: Integer TODO: FIND THIS ONE OUT!
} deriving Show

-- TODO: use group 14!
dhGroup1 = DHGroup 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF 2


dhComputeExchangeHash :: SshString -> SshString -> SshString -> SshString -> SshString -> Integer -> Integer -> SshString -> SshString
dhComputeExchangeHash clientIdent serverIdent clientKexPayload serverKexPayload hostKey e f sharedSecret =
  bytestringDigest $ sha1 $ runPut $ do -- TODO make sha1 configurable
    put clientIdent
    put serverIdent
    put clientKexPayload
    put serverKexPayload
    put hostKey
    putMPInt e
    putMPInt f
    put sharedSecret

dhComputeSharedSecret :: Integer -> Integer -> Integer -> SshString
dhComputeSharedSecret f x p = runPut $ putMPInt $ modexp f x p


filterNewlines :: SshString -> SshString
filterNewlines s = B.filter (not . (\x -> x == '\n' || x == '\r')) s -- Filter only the FINAL \r\n??? ###

--TODO use hash
diffieHellmanGroup :: DHGroup -> [KEXAlgorithm] -> [HostKeyAlgorithm] -> [CryptionAlgorithm] -> [CryptionAlgorithm] -> [HashMac] -> [HashMac] -> SshString -> SshString -> SshString -> (SshString -> SshString) -> (Socket -> IO Packet) -> Socket -> IO ConnectionData
diffieHellmanGroup (DHGroup p g) clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs clientVersionString rawClientKexInit rawServerKexInit makeTransportPacket getPacket s = do
    let q = (p - 1) `div` 2 -- let's *assume* this is the order of the subgroup?
    x <- randIntegerOneToNMinusOne q
    let e = modexp g x p
        dhInit = KEXDHInit e
    putStrLn $ show dhInit
    sendAll s $ makeTransportPacket $ runPut $ putPacket dhInit dhKexPutPacketHelper
    dhReply <- getPacket s
    putStrLn $ show dhReply
    newKeys <- getPacket s
    putStrLn $ show newKeys

    let sharedSecret = dhComputeSharedSecret (dh_f dhReply) x p
        cvs = filterNewlines clientVersionString
        serverVersion = "OpenSSH_5.1p1 Debian-5" -- ### TODO
        svs = filterNewlines serverVersion
        hostKey = dh_hostKeyAndCerts dhReply -- AND certs? ###
        exchangeHash = dhComputeExchangeHash {-hash-} cvs svs rawClientKexInit rawServerKexInit hostKey e (dh_f dhReply) sharedSecret
        sId = undefined --
        theMap = \c -> createKeyData sharedSecret exchangeHash c sId
        [c2sIV, s2cIV, c2sEncKey, s2cEncKey, c2sIntKey, s2cIntKey] = map theMap ['A' .. 'F']
        cd = ConnectionData sId (makeWord8 sharedSecret) (makeWord8 exchangeHash) c2sIV s2cIV c2sEncKey s2cEncKey c2sIntKey s2cIntKey
    putStrLn "A"
    putStrLn $ show hostKey
    putStrLn "B"
    putStrLn $ show exchangeHash
    case newKeys of
        NewKeys -> return cd
        _       -> error "Expected NEWKEYS"

dhKexInitGetHelper :: [KEXAlgorithm] -> [HostKeyAlgorithm] -> [CryptionAlgorithm] -> [CryptionAlgorithm] -> [HashMac] -> [HashMac] -> Get Packet
dhKexInitGetHelper clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs = do
    c <- replicateM 16 getWord8
    ka <- parseServerNameListFiltered id (map kexName clientKEXAlgos) `liftM` get
    hka <- parseServerNameListFiltered id (map hostKeyAlgorithmName clientHostKeys) `liftM` get
    ecs <- parseServerNameListFiltered id (map cryptoName clientCryptos) `liftM` get
    esc <- parseServerNameListFiltered id (map cryptoName serverCryptos) `liftM` get
    mcs <- parseServerNameListFiltered id (map hashName clientHashMacs) `liftM` get
    msc <- parseServerNameListFiltered id (map hashName serverHashMacs) `liftM` get
    return $ KEXInit B.empty c ka hka ecs esc mcs msc

dhKexPutPacketHelper :: Packet -> Put
dhKexPutPacketHelper (KEXInit _ c ka hka ecs esc mcs msc) = do
    put (20 :: Word8) -- KEXInit
    forM c put -- Cookie, 16 bytes
    put $ NameList { names = ka }
    put $ NameList { names = hka }
    put $ NameList { names = esc }
    put $ NameList { names = ecs }
    put $ NameList { names = mcs }
    put $ NameList { names = msc }
    put $ NameList { names = ["none"] } -- compression
    put $ NameList { names = ["none"] } -- compression
    put $ NameList { names = [] }
    put $ NameList { names = [] }
    put $ (0 :: Word8) -- firstKexFollows
    putWord32 0 -- Future Use
dhKexPutPacketHelper p = error $ "This should not happen" ++ show p
