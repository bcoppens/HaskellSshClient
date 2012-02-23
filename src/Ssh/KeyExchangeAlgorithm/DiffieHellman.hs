{-# LANGUAGE OverloadedStrings #-}

-- | Diffie-Hellman Key Exchange
module Ssh.KeyExchangeAlgorithm.DiffieHellman (
      diffieHellmanGroup
    , dhGroup1
) where

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

import Control.Monad
import qualified Control.Monad.State as MS
import Data.Bits
import qualified Data.ByteString.Lazy as B

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers

import Data.Digest.Pure.SHA

import Ssh.NetworkIO
import Ssh.Packet
import Ssh.KeyExchangeAlgorithm
import Ssh.PublicKeyAlgorithm
import Ssh.HostKeyAlgorithm
import Ssh.ConnectionData
import Ssh.Cryption
import Ssh.Transport
import Ssh.HashMac
import Ssh.Debug
import Ssh.String

data DHGroup = DHGroup {
      safePrime :: Integer
    , generator :: Integer
    -- , orderOfSubgroup :: Integer TODO: FIND THIS ONE OUT!
} deriving Show

-- TODO: use group 14!
-- | "diffie-hellman-group1-sha1" uses Oakley Group 2! Not Group 1!
dhGroup1 = DHGroup 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF 2


-- | Computes the Exchange Hash as specified on p23 of the SSH Transport Layer Protocol (RFC 4253)
dhComputeExchangeHash :: SshString -> SshString -> SshString -> SshString -> SshString -> Integer -> Integer -> SshString -> SshString
dhComputeExchangeHash clientIdent serverIdent clientKexPayload serverKexPayload hostKey e f sharedSecret =
  bytestringDigest $ sha1 $ runPut $ do -- TODO make sha1 configurable
    putString clientIdent
    putString serverIdent
    putString clientKexPayload
    putString serverKexPayload
    putString hostKey
    putMPInt e
    putMPInt f
    putRawByteString sharedSecret -- has already been runPut through putMPInt

-- | String representation of the shared secret that we compute
dhComputeSharedSecret :: Integer -> Integer -> Integer -> SshString
dhComputeSharedSecret f x p = runPut $ putMPInt $ modexp f x p

convert = toEnum . fromEnum

-- | The key exchange needs to filter out the newlines of the version string
filterNewlines :: SshString -> SshString
filterNewlines s = B.filter (not . (\x -> x == convert '\n' || x == convert '\r')) s -- Filter only the FINAL \r\n??? ###

--TODO use hash
-- | Perform Diffie-Hellman key exchange
diffieHellmanGroup :: DHGroup -> SshString -> SshString -> SshConnection ConnectionData
diffieHellmanGroup (DHGroup p g) rawClientKexInit rawServerKexInit = do
    transportInfo <- MS.get

    -- Compute and initialize the various DH parameters
    let q = (p - 1) `div` 2 -- let's *assume* this is the order of the subgroup?
    x <- MS.liftIO $ randIntegerOneToNMinusOne q

    let e = modexp g x p
        dhInit = KEXDHInit e

    printDebugLifted logLowLevelDebug $ show dhInit

    -- Send the packet with our initial DH parameters, and get their reply
    sPutPacket dhInit
    dhReply <- sGetPacket

    printDebugLifted logLowLevelDebug $ show dhReply

    -- Verify that this server's host key is known
    let hka = serverHostKeyAlgorithm transportInfo
        hostKey = dh_hostKeyAndCerts dhReply
    -- hostKeyOk <- MS.liftIO $ checkHostKey hka (hostName transportInfo) hostKey
    let hostKeyOk = True
    printDebugLifted logDebug $ "Host key accepted: " ++ show hostKeyOk
    -- TODO: act on this information!

    -- We expect the server to put into use the new keys and confirm that. So get their packet confirming that
    newKeys <- sGetPacket

    printDebugLifted logLowLevelDebug $ show newKeys

    -- Compute the shared secret
    let sharedSecret = dhComputeSharedSecret (dh_f dhReply) x p
        cvs = filterNewlines $ clientVersionString transportInfo
        svs = filterNewlines $ serverVersionString transportInfo
        hostKey = dh_hostKeyAndCerts dhReply -- AND certs? ###

        -- With all this data, we can now compute the exchange hash
        exchangeHash = dhComputeExchangeHash {-hash-} cvs svs rawClientKexInit rawServerKexInit hostKey e (dh_f dhReply) sharedSecret

        -- Is this our initial key exchange, or a re-key? If this is the initial exchange, initialize the sessionId with the exchangeHash. Otherwise, reuse the sId
        sId = case maybeConnectionData transportInfo of
                Nothing -> B.unpack exchangeHash
                Just cd -> sessionId cd

        -- Compute the key data
        theMap = \c -> createKeyData sharedSecret exchangeHash c exchangeHash
        [c2sIV, s2cIV, c2sEncKey, s2cEncKey, c2sIntKey, s2cIntKey] = map (take 128 . theMap . convert) ['A' .. 'F'] -- TODO take 128 -> the right value!

        -- Now we have all data that is computed in the key exchange, store this data
        cd = ConnectionData sId (makeWord8 sharedSecret) (makeWord8 exchangeHash) c2sIV s2cIV c2sEncKey s2cEncKey c2sIntKey s2cIntKey

    -- Verify if the dh_H_signature the server sent, is actually signed by the server's (accepted) key
    let signature = dh_H_signature dhReply
        doVerify  = verify $ hostKeyPublicKeyAlgorithm hka
    signatureOk <- MS.liftIO $ doVerify hostKey exchangeHash signature

    -- TODO: act on this info!
    printDebugLifted logDebug $ "Signature signed by Host Key? " ++ show signatureOk

    printDebugLifted logLowLevelDebug $ "Shared Secret: \n" ++ debugRawStringData sharedSecret

    case newKeys of
        NewKeys -> return cd
        _       -> error "Expected NEWKEYS"
