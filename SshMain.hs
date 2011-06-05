import Network
import Data.Binary.Put
import Data.Word
import Control.Monad
import Data.List
import Data.Maybe
import qualified Data.ByteString.Lazy.Char8 as B

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
import Ssh.KeyExchange.DiffieHellman
import Ssh.HashMac
import Ssh.HostKeyAlgorithm
import Ssh.Transport

import Debug.Trace
debug = putStrLn

type SshString = B.ByteString

clientVersionString = "SSH-2.0-BartSSHaskell-0.0.1 This is crappy software!\r\n"

chunkUpString :: Int -> SshString -> [[Word8]] -- bytesPerChunk string
chunkUpString bpc s = chunkIt bytes []
    where bytes = map (toEnum . fromEnum) $ B.unpack s
          chunkIt :: [Word8] -> [[Word8]] -> [[Word8]]
          chunkIt b acc | todo == []  = new
                        | otherwise   = chunkIt todo new
                        where (chunk, todo)   = splitAt bpc b
                              new             = acc ++ [chunk] -- TODO

clientCryptos = [ (CryptionAlgorithm (B.pack "aes256-cbc") (aesEncrypt 256) (aesDecrypt 256) 128) ]

clientHashMacs = [ HashMac (B.pack "hmac-sha1") (error "OEPS") 0 ]

rsaHostKey = HostKeyAlgorithm (B.pack "ssh-rsa")
clientHostKeys = [rsaHostKey]

dhGroup1KEXAlgo = KEXAlgorithm (B.pack "diffie-hellman-group1-sha1") (diffieHellmanGroup dhGroup1 {-sha1-} clientKEXAlgos clientHostKeys clientCryptos clientCryptos clientHashMacs clientHashMacs) -- IEW RECURSIVE
clientKEXAlgos = [dhGroup1KEXAlgo]

doKex :: [KEXAlgorithm] -> [HostKeyAlgorithm] -> [CryptionAlgorithm] -> [CryptionAlgorithm] -> [HashMac] -> [HashMac] -> Socket -> (SshTransport -> Socket -> IO ServerPacket) -> IO ConnectionData
doKex clientKEXAlgos clientHostKeys clientCryptos serverCryptos clientHashMacs serverHashMacs s getPacket = do
    --cookie <- fmap (fromInteger . toInteger) $ replicateM 16 $ (randomRIO (0, 255 :: Int)) :: IO [Word8]
    let cookie = replicate 16 (-1 :: Word8) -- TODO random
    let clientKex = KEXInit B.empty cookie (map kexName clientKEXAlgos) (map hostKeyAlgorithmName clientHostKeys) (map cryptoName clientCryptos) (map cryptoName serverCryptos) (map hashName clientHashMacs) (map hashName serverHashMacs)
    let initialTransport = SshTransport noCrypto noHashMac
    sendAll s $ makeSshPacket initialTransport $ runPut $ dhKexPutPacketHelper clientKex -- TODO make configurable
    putStrLn "Mu"
    serverKex <- getPacket initialTransport s
    putStrLn $ show serverKex
    -- assert KEXInit packet
    let kex   = head $ kex_algos serverKex
        kexFn = fromJust $ find (\x -> kexName x == kex) clientKEXAlgos
        rawClientKexInit = rawPacket clientKex
        rawServerKexInit = rawPacket serverKex
        makeTransportPacket = makeSshPacket initialTransport
    connectiondata <- handleKex kexFn (B.pack clientVersionString) rawClientKexInit rawServerKexInit makeTransportPacket (getPacket initialTransport) s
    sendAll s $ makeSshPacket initialTransport $ runPut $ putPacket NewKeys undefined
    sendAll s $ makeSshPacket initialTransport $ runPut $ putPacket (ServiceRequest $ B.pack "ssh-wololooo") undefined
    putStrLn "KEX DONE?"
    return connectiondata


getServerVersionString :: Socket -> IO String
getServerVersionString s = do l <- sockReadLine s
                              if B.pack "SSH-2.0" `B.isPrefixOf` l
                                then return . B.unpack $ l
                                else getServerVersionString s

processPacket :: ServerPacket -> IO ()
processPacket p = putStrLn $ "processPacket:" ++ show p

--computeEncryptionInfo :: HashFunction -> String -> String

clientLoop :: Socket -> SshTransport -> IO ()
clientLoop = error "clientloop"


main :: IO ()
main = do
    connection <- connect' "localhost" 22
    --hSetBuffering connection $ BlockBuffering Nothing
    serverVersion <- getServerVersionString connection
    debug serverVersion
    sendAll connection $ B.pack clientVersionString
    let dhMeh = dhKexInitGetHelper clientKEXAlgos clientHostKeys clientCryptos clientCryptos clientHashMacs clientHashMacs -- TODO
    cd <- doKex clientKEXAlgos clientHostKeys clientCryptos clientCryptos clientHashMacs clientHashMacs connection (sGetPacket dhMeh)
    --requestService (B.pack "ssh-userauth")
    clientLoop connection undefined
    sClose connection
    where
      -- Higher-level connect function
      connect' hostname port = do
        protocol <- getProtocolNumber "tcp"
        entry <- getHostByName hostname
        sock <- socket (hostFamily entry) Stream protocol
        connect sock $ SockAddrInet (fromIntegral port) $ hostAddress entry
        return sock
