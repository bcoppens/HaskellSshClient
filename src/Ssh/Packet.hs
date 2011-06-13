{-# LANGUAGE OverloadedStrings #-}

module Ssh.Packet (
      Packet (..)
    , ClientPacket
    , ServerPacket
    , annotatePacketWithPayload
    , putPacket
    , getPacket
) where

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Control.Monad
import qualified Data.ByteString.Lazy as B

import Ssh.NetworkIO

type SshString = B.ByteString


data Packet =
    Disconnect { -- 1
      disc_code :: Int
    , disc_description :: SshString
    , disc_language :: SshString
    }
   | Ignore { -- 2
     ignoreData :: SshString
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
  | UserAuthRequest { -- 50
      authUserName :: SshString
    , authServiceName :: SshString
    , authMethodName :: SshString
    , authPayload :: SshString
    }
  | UserAuthFailure { -- 51
      authenticationsCanContinue :: [SshString]
    , authPartialSucces :: Bool
    }
  | UserAuthSuccess -- 52
  | UserAuthBanner { -- 53
      bannerMessage :: SshString
    , bannerLanguage :: SshString
    }
    deriving Show

type ClientPacket = Packet
type ServerPacket = Packet

annotatePacketWithPayload :: ServerPacket -> SshString -> ServerPacket 
annotatePacketWithPayload packet@(KEXInit _ _ _ _ _ _ _ _) pl = packet { rawPacket = pl }
annotatePacketWithPayload p _ = p


putPacket :: Packet -> Put
putPacket (ServiceRequest n) = do
    put (5 :: Word8)
    putString n
putPacket (KEXInit _ c ka hka ecs esc mcs msc) = do
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
putPacket NewKeys = put (21 :: Word8)
putPacket (KEXDHInit e) = do
    put (30 :: Word8)
    putMPInt e
putPacket (UserAuthRequest userName serviceName methodName payload) = do
    put (50 :: Word8)
    putString userName
    putString serviceName
    putString methodName
    putRawByteString payload

getPacket :: Get Packet
getPacket = do
    msg <- getWord8
    case msg of
        1  -> do -- Disconnect
            r <- fromEnum `liftM` getWord32
            desc <- getString
            lang <- getString
            return $ Disconnect r desc lang
        2 -> do -- Ignore
            s <-getString
            return $ Ignore s
        6  -> do -- ServiceAccept
            s <- getString
            return $ ServiceAccept s
        20 -> do -- KEXInit
            c <- replicateM 16 getWord8
            ka <- names `liftM` get
            hka <- names `liftM` get
            ecs <- names `liftM` get
            esc <- names `liftM` get
            mcs <- names `liftM` get
            msc <- names `liftM` get
            return $ KEXInit B.empty c ka hka ecs esc mcs msc -- We'll have to filter out the ones we don't know afterwards!
        21 -> return NewKeys
        31 -> do -- KEXDHReply
            k_S <- getString
            f <- getMPInt
            h_sig <- getString
            return $ KEXDHReply k_S f h_sig
        51 -> do -- UserAuthFailure
            canContinue    <- names `liftM` get
            partialSuccess <- getBool
            return $ UserAuthFailure canContinue partialSuccess
        52 -> return UserAuthSuccess
        53 -> do -- UserAuthBanner
            banner <- getString
            lang   <- getString
            return $ UserAuthBanner banner lang
        _ -> error $ "unhandled getPacket, msg was " ++ show msg

{-
instance Binary Packet where
    put = putPacket
    get = getPacket
-}



