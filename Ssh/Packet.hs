module Ssh.Packet (
      Packet (..)
    , parseServerNameListFiltered
    , ClientPacket
    , ServerPacket
    , annotatePacketWithPayload
    , putPacket
    , getPacket
) where

import Network
import System.IO
import System.Random
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Char
import Data.Word
import Control.Monad
import qualified Control.Monad.State as MS
import Data.List
import Data.Maybe
import Data.Monoid
import Data.Bits
import qualified Data.ByteString.Lazy.Char8 as B
import qualified Data.ByteString.Char8 as BS

import Data.Int
import Network.BSD ( HostEntry (..), getProtocolNumber, getHostByName
                   , hostAddress
                   )
import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import Network.Socket.ByteString.Lazy

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers

import Data.HMAC
import Data.Digest.Pure.SHA
import qualified Codec.Encryption.AES as AES
import Codec.Utils
import Data.LargeWord

import Debug.Trace

import Ssh.NetworkIO

type SshString = B.ByteString


data Packet =
    Disconnect { -- 1
      disc_code :: Int
    , disc_description :: String
    , disc_language :: String
    }
   | ServiceRequest { -- 5
      serviceReqName :: SshString
   }
   | ServiceAccept { -- 6
      serviceAccName :: SshString
   }
   | KEXInit { -- 20
       rawPacket :: SshString -- Because we have to use it in hashes
    ,  kexCookie :: [Word8] -- 16 bytes
      -- Possible algos
    , kex_algos :: [SshString] -- [KEXAlgorithm]
    , host_key_algos :: [SshString] -- [HostKeyAlgorithm]
    , enc_c2s :: [SshString] -- [CryptionAlgorithm]
    , enc_s2c :: [SshString] -- [CryptionAlgorithm]
    , mac_c2s :: [SshString] -- [HashMac]
    , mac_s2c :: [SshString] -- [HashMac]
    --, compression
    --, languages
    }
  | NewKeys -- 21
  | KEXDHInit { -- 30
      dh_e :: Integer
    }
  | KEXDHReply { -- 31
      dh_hostKeyAndCerts :: SshString -- K_S
    , dh_f :: Integer
    , dh_H_signature :: SshString
    }
    deriving Show

type ClientPacket = Packet
type ServerPacket = Packet

annotatePacketWithPayload :: ServerPacket -> SshString -> ServerPacket 
annotatePacketWithPayload packet@(KEXInit _ _ _ _ _ _ _ _) pl = packet { rawPacket = pl }
annotatePacketWithPayload p _ = p


putPacket :: Packet -> (Packet -> Put) -> Put
putPacket (ServiceRequest n) _ = do
    put (5 :: Word8)
    putString n
putPacket p@(KEXInit _ _ _ _ _ _ _ _) helper = helper p
putPacket NewKeys _ = put (21 :: Word8)
putPacket (KEXDHInit e) _ = do
    put (30 :: Word8)
    putMPInt e

-- When reading a namelist, we handily drop all the entries that we don't know about. Order in the server list is irrelevant, client's first is chosen
parseServerNameListFiltered :: (a -> SshString) -> [a] -> NameList -> [a]
parseServerNameListFiltered getName clientList serverList = filter ((`elem` (names serverList)) . getName) clientList

getPacket :: (Get Packet) -> Get Packet
getPacket kexInitHelper = do
    msg <- getWord8
    case msg of
        1  -> do -- Disconnect
            r <- fromEnum `liftM` getWord32
            desc <- B.unpack `liftM` getString
            lang <- B.unpack `liftM` getString
            return $ Disconnect r desc lang
        6  -> do -- ServiceAccept
            s <- getString
            return $ ServiceAccept s
        20 -> -- KEXInit
            kexInitHelper
        21 -> return NewKeys
        31 -> do -- KEXDHReply
            k_S <- getString
            f <- getMPInt
            h_sig <- getString
            return $ KEXDHReply k_S f h_sig
        _ -> error $ "unhandled getPacket, msg was " -- ++ show msg

{-
instance Binary Packet where
    put = putPacket
    get = getPacket
-}



