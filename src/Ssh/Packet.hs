{-# LANGUAGE OverloadedStrings #-}
-- | SSH Packet definition, including the functions needed for binary input/output with 'Get'/'Put'
module Ssh.Packet (
    -- | Data Types
      Packet (..)
    , ClientPacket
    , ServerPacket
    -- | Decoding and encoding
    , putPacket
    , getPacket
    -- | Helper functions
    , annotatePacketWithPayload
) where

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Control.Monad
import qualified Data.ByteString.Lazy as B

import Ssh.NetworkIO

type SshString = B.ByteString

-- | This should define all SSH packets defined by the standard
data Packet =
    Disconnect { -- 1
      disc_code :: Int
    , disc_description :: SshString
    , disc_language :: SshString
    }
   | Ignore { -- 2
     ignoreData :: SshString
   }
   | Unimplemented { -- 3
     rejectedSequenceNumber :: Int
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
  | GlobalRequest { -- 80
      requestName :: SshString
    , wantsReply :: Bool
    , requestPayload :: SshString
  }
  | RequestSuccess { -- 81
      requestData :: SshString
  }
  | RequestFailure -- 82
  | ChannelOpen { -- 90
      channelType :: SshString
    , channelNr :: Int
    , initWindowSize :: Int
    , maxPacketSize :: Int
    , channelPayload :: SshString
  }
  | ChannelOpenConfirmation { -- 91
      recipientChannelNr :: Int
    , senderChannelNr :: Int
    , initWindowSize :: Int
    , maxPacketSize :: Int
    , channelPayload :: SshString
  }
  | ChannelOpenFailure { -- 92
      channelNr :: Int
    , reasonCode :: Int
    , description :: SshString
    , language :: SshString
  }
  | ChannelWindowAdjust { -- 93
      channelNr :: Int
    , bytesToAdd :: Int
  }
  | ChannelData { -- 94
      channelNr :: Int
    , channelPayload :: SshString
  }
  | ChannelExtendedData { --95
      channelNr :: Int
    , extendedDataTypeCode :: Int
    , channelPayload :: SshString
  }
  | ChannelEof { -- 96
      channelNr :: Int
  }
  | ChannelClose { -- 97
      channelNr :: Int
  }
  | ChannelRequest { -- 98
      channelNr :: Int
    , requestType :: SshString
    , wantsReply :: Bool
    , channelPayload :: SshString
  }
  | ChannelSuccess { -- 99
      channelNr :: Int
  }
  | ChannelFailure { -- 100
      channelNr :: Int
  }
    deriving Show

-- | This is a packet sent by the client
type ClientPacket = Packet
-- | This is a packet sent by the server
type ServerPacket = Packet

-- TODO not needed anymore currently?
-- | the KEXInit can contain its own payload encoded
annotatePacketWithPayload :: ServerPacket -> SshString -> ServerPacket 
annotatePacketWithPayload packet@(KEXInit _ _ _ _ _ _ _ _) pl = packet { rawPacket = pl }
annotatePacketWithPayload p _ = p


-- | Write a 'Packet', and make a 'Put' out of it which we can 'runPut' into an 'SshByteString'
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
putPacket (ChannelOpen channelType channelNr initWindowSize maxPacketSize channelPayload) = do
    put (90 :: Word8)
    putString channelType
    putWord32 $ (toEnum . fromEnum) channelNr
    putWord32 $ (toEnum . fromEnum) initWindowSize
    putWord32 $ (toEnum . fromEnum) maxPacketSize
    putRawByteString channelPayload

-- | Can decode a 'Packet' from an 'SshBytestring' using 'runGet'
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
        3  -> do -- Unimplemented
            seqNr <- fromEnum `liftM` getWord32
            return $ Unimplemented seqNr
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
        91 -> do -- ChannelOpenConfirmation
            recipientChannelNr <- fromEnum `liftM` getWord32
            senderChannelNr <- fromEnum `liftM` getWord32
            initWindowSize <- fromEnum `liftM` getWord32
            maxPacketSize <- fromEnum `liftM` getWord32
            payload <- getRemainingLazyByteString
            return $ ChannelOpenConfirmation recipientChannelNr senderChannelNr initWindowSize maxPacketSize payload
        _ -> error $ "unhandled getPacket, msg was " ++ show msg

{-
instance Binary Packet where
    put = putPacket
    get = getPacket
-}



