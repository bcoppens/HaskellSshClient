{-# LANGUAGE OverloadedStrings #-}

-- | Digital Signature Standard signatures, in the 'raw' format (as specified in RFC 4253), using OpenSSL DSA routines
module Ssh.PublicKeyAlgorithm.RawDSS (
      mkRawDSSSigner
) where

import Data.Binary.Get
import Data.Binary.Put
import Data.Maybe

-- We use OpenSSL for input of the files, and the signing/verifying
import qualified OpenSSL.PEM as PEM
import qualified OpenSSL.DSA as DSA
import OpenSSL.EVP.PKey

import qualified Data.Digest.SHA1 as SHA1

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString as BS

import Ssh.Cryption
import Ssh.NetworkIO
import Ssh.PublicKeyAlgorithm
import Ssh.String

-- | Encode r,s as a 'dss_signature_blob', which contains the two 160 bit integers without padding or length, unsigned, in network byte order
encodeRS :: Integer -> Integer -> Put
encodeRS r s = do
    -- Make [Word8]s of length 20 of r and s
    let r' = B.pack $ padTo 20 0 $ toBigEndian r
        s' = B.pack $ padTo 20 0 $ toBigEndian s
    putRawByteString r'
    putRawByteString s'

-- | Put an (r, s) pair (which should be 160 bit integers) into a ssh-dss signature
putDSSSignature :: Integer -> Integer -> Put
putDSSSignature r s = do
    putString "ssh-dss"
    let blob = runPut $ encodeRS r s
    putString blob

-- | Sign with a keypair some string, and turn it into something SSH recognizes as a signature
dsaSign :: SomeKeyPair -> SshString -> IO SshString
dsaSign kp toSign = do
    let -- signDigestedDataWithDSA signs data digested with sha1. SHA1 is required by the DSA standard (FIPS 186-2)
        digestRaw = SHA1.hash $ B.unpack toSign :: SHA1.Word160

        -- The digest is actually a rather useless Word160, convert it back to a more useful (strict) ByteString
        digested = BS.pack $ padToInWord8 20 $ SHA1.toInteger digestRaw

        -- the pk is a SomeKeyPair. Cast it (sigh) to a real DSAPubKey
        mDsaKeyPair = toKeyPair kp
        dsaKeyPair  = fromJust mDsaKeyPair
    -- Actually sign the digest
    (r, s) <- DSA.signDigestedDataWithDSA dsaKeyPair digested

    -- Encode the resulting signature
    return $ runPut $ putDSSSignature r s

-- | Convert a 'SomePublicKey which is hopefully a DSA(Pub)KeyPair into the ssh-dss key format
rawDSSKeyBlob :: SomeKeyPair -> SshString
rawDSSKeyBlob pubkey =
    let mDsaPubKey = toKeyPair pubkey
        dsaPubKey  = fromJust mDsaPubKey

        -- Read the data from the public key; public key = y = g^x
        (p, q, g, y) = DSA.dsaPubKeyToTuple dsaPubKey
    -- The actual key format
    in runPut $ do
        putString  "ssh-dss"
        putMPInt   p
        putMPInt   q
        putMPInt   g
        putMPInt   y

-- | Read key information from a private key file with which we can sign. Also get the public key information from this file
mkRawDSSSigner :: String -> IO PublicKeyAlgorithm
mkRawDSSSigner privateKeyFile = do
    -- Read the private key file. Also contains the public part
    privateKey <- readFile privateKeyFile

    -- TODO! Use a different PemPasswordSupply
    -- TODO: should be scrubbed from memory?
    -- Read the private key into something we can use
    keyPair <- PEM.readPrivateKey privateKey PEM.PwNone

    -- We'll sign strings with this key pair
    let signer = dsaSign keyPair

    -- And the public key blob
    let pubKeyBlob = rawDSSKeyBlob keyPair

    return $ PublicKeyAlgorithm "ssh-dss" (error "VERIFY") signer pubKeyBlob
