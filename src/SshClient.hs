{-# LANGUAGE OverloadedStrings,CPP #-}

module Main (
      main
) where

import Network
import Data.Binary.Put
import Data.Word
import Control.Concurrent
import Control.Monad
import qualified Control.Monad.State as MS
import Data.List
import Data.Maybe
import qualified Data.ByteString.Lazy as B
import qualified Data.Map as Map

import System.IO
import System.Environment
import System.Console.GetOpt
import GHC.IO.Handle

import Network.BSD ( HostEntry (..), getProtocolNumber, getHostByName
                   , hostAddress
                   )
import Network.Socket (Socket, SockAddr (..), SocketType (..), connect, socketToHandle)
import qualified Network.Socket (socket)
import Network.Socket.ByteString.Lazy

-- Non-'standard' functionality
import OpenSSL.BN -- modexp, random Integers

import Debug.Trace

import Ssh.NetworkIO
import Ssh.Packet
import Ssh.KeyExchange
import Ssh.Cryption
import Ssh.ConnectionData
import Ssh.KeyExchangeAlgorithm
import Ssh.KeyExchangeAlgorithm.DiffieHellman
import Ssh.KeyExchange
import Ssh.HashMac
import Ssh.PublicKeyAlgorithm
import Ssh.PublicKeyAlgorithm.RawDSS
import Ssh.Transport
import Ssh.Authentication
import Ssh.Authentication.Password
import Ssh.Authentication.PublicKey
import Ssh.Debug
import Ssh.Channel
import Ssh.Channel.Session
import Ssh.String

import Debug.Trace
debug = putStrLn


data Options = Options {
      privateKeyFile :: Maybe String
    , port :: Int
} deriving Show

defaultOptions = Options Nothing 22

options :: [OptDescr (Options -> Options)]
options = [
      Option [] ["privatekeyfile"] (OptArg ((\f opts -> opts { privateKeyFile = Just f }) . fromMaybe "") "file") "Location of the (DSA) private key file to use, if any"
    , Option ['p'] ["port"] (OptArg ((\p opts -> opts { port = read p } ) . fromMaybe "22") "port") "Port to connect to"
  ]

-- | Result: first are the options, second should be the 'non-option' user@hostname
getOptions :: [String] -> IO (Options, [String])
getOptions argv =
    case getOpt Permute options argv of
        -- (_,[],_)   -> ioError (userError ("No hostname specified!\n" ++ (usageInfo header options))) -- TODO: uncomment this in the final code, makes sure the user gave a hostname :)
        (o,n,[]  ) -> return  (foldl (flip id) defaultOptions o, n)
        (_,_,errs) -> ioError (userError (concat errs ++ usageInfo header options))
    where header = "Usage: SshClient [OPTIONS...] [user@]hostname"

clientVersionString = "SSH-2.0-BartSSHaskell-0.0.1 This is crappy software!\r\n"

clientCryptos = [
      (CryptionAlgorithm "aes256-ctr" (ctrAesEncrypt 256) (ctrAesDecrypt 256) 16),
      (CryptionAlgorithm "aes256-cbc" (cbcAesEncrypt 256) (cbcAesDecrypt 256) 16)
    ]

clientHashMacs = [ sha1HashMac ]

rsaHostKey = PublicKeyAlgorithm "ssh-rsa" (error "RSA HOSTKEY") (error "RSA HOSTKEY") (error "RSA HOSTKEY")

clientHostKeys = [rsaHostKey]

dhGroup1KEXAlgo = KeyExchangeAlgorithm "diffie-hellman-group1-sha1" (diffieHellmanGroup dhGroup1 {-sha1-})
clientKEXAlgos = [dhGroup1KEXAlgo]

getServerVersionString :: Socket -> IO SshString
getServerVersionString s = do l <- sockReadLine s
                              if "SSH-2.0" `B.isPrefixOf` l
                                then return l
                                else getServerVersionString s

processPacket :: ServerPacket -> IO ()
processPacket p = putStrLn $ "processPacket:" ++ show p

-- TODO: get port!
-- | Parse commandline argument for username@hostname. If just hostname is specified, get username from USER environment variable.
--   If no commandline argument is given, use bartcopp@localhost for debugging purposes
--   Returns (username, hostname). Since we first resolve the hostname, that's a regular 'String', since we'll send the username, that's an 'SshString'
getUserAndHostNameFromArguments :: [String] -> IO (SshString, String)
getUserAndHostNameFromArguments args = do
    if null args || args == ["localhost"]
        then return ("bartcopp", "localhost")
        else parseUserAndHostName $ head args

-- | Parses argument & returns username@hostname info like documented in 'getUserAndHostNameFromArguments'
parseUserAndHostName :: String -> IO (SshString, String)
parseUserAndHostName s = do
    let (left, right) = break (== '@') s

    -- If it contains no @, the right is empty, and the left is the hostname. Get the username
    if null right
        then do
            username <- getEnv "USER" -- TODO: can fail!?
            return (B.pack $ convert username, left)
        else
            return (B.pack $ convert left, drop 1 right) -- drop the @ from the hostname

        where
            convert = map (toEnum . fromEnum)

-- | This is the main client loop, performing first the authentication, then opening channels, etc...
clientLoop :: SshString -> SshString -> Options -> ConnectionData -> SshConnection ()
clientLoop username hostname options cd = do
    ti <- MS.get

    -- Which authentication methods do we support? password always, but perhaps the user specified a private key file (DSA only for now)
    authMethods <-
        case privateKeyFile options of
            Nothing   -> return [passwordAuth]
            Just file -> do
                publicKey <- MS.liftIO $ mkRawDSSSigner file
                return $ [publicKeyAuth publicKey, passwordAuth]

    -- Try to authenticate with the specified methods
    authOk <- authenticate username hostname "ssh-connection" authMethods
    MS.liftIO $ printDebug logDebug $ "Authentication OK? " ++ show authOk

    runGlobalChannelsToConnection initialGlobalChannelsState (doShell ti) -- demoExec
    where
      demoExec = do -- execute a command remotely, and show the result. As a test, execute cat /proc/cpuinfo
        channel <- openChannel sessionHandler ""                -- Open a channel
        insertChannel channel $ requestExec "cat /proc/cpuinfo" -- Request Exec
        loop -- Loop
            where
                loop :: Channels ()
                loop = do
                    packet <- MS.lift $ sGetPacket
                    handleChannel packet
                    loop

      doShell ti = do -- request a shell remotely
        channel <- openChannel sessionHandler ""            -- Open a channel
        safeInfo   <- MS.liftIO $ newEmptyMVar
        insertChannel channel $ requestShell safeInfo -- Request a shell

        globalInfo <- MS.get
        connection <- MS.lift $ MS.get
        MS.liftIO $ putMVar safeInfo (globalInfo, connection)

        let sshSocket = socket connection

        loop safeInfo sshSocket -- Loop
            where
                loop safeInfo sshSocket = do
                    -- Wait for input on the socket
                    MS.liftIO $ waitForSockInput sshSocket

                    -- There was input, now take the state to read it.
                    (globalInfo, connection) <- MS.liftIO $ takeMVar safeInfo

                    -- Update our state, it might have been changed!
                    MS.put globalInfo
                    MS.lift $ MS.put connection

                    -- Read & handle packet
                    packet <- MS.lift $ sGetPacket
                    handleChannel packet

                    -- Put back the changed state
                    globalInfo' <- MS.get
                    connection' <- MS.lift $ MS.get
                    MS.liftIO $ putMVar safeInfo (globalInfo', connection')

                    -- We opened a channel. If 0 channels are in use, this means we/the server closed all our channel(s) => terminate our loop; otherwise => keep running
                    case Map.size $ usedChannels globalInfo' of
                        0         -> return ()
                        otherwise -> loop safeInfo sshSocket

main :: IO ()
main = do
    -- Parse the arguments
    args    <- getArgs
    (options, location) <- getOptions args

    -- Get username and hostname
    (username, hostname) <- getUserAndHostNameFromArguments location

    -- Connect to the server
    connection <- connect' hostname $ port options
    --hSetBuffering connection $ BlockBuffering Nothing

    -- Get the server's version string, send our version string
    serverVersion <- getServerVersionString connection
    printDebug logLowLevelDebug $ show serverVersion
    sendAll connection clientVersionString

    -- TODO remove runState!
    -- Do the Key Exchange, initialize the SshConnection
    sshSock <- mkSocket connection

    let tinfo = mkTransportInfo sshSock (error "Client2ServerTransport") [] 0 (error "Server2ClientTransport") [] 0 Nothing

    (cd, newState) <- flip MS.runStateT tinfo $
        doKex clientVersionString serverVersion clientKEXAlgos clientHostKeys clientCryptos clientCryptos clientHashMacs clientHashMacs

    -- Run the client loop, i.e. the real part
    result <- MS.execStateT (clientLoop username (B.pack $ map (toEnum . fromEnum) $ hostname) options cd) newState

#ifdef DEBUG
    -- We might be being verbose, perhaps print out some statistics on the connection
    printDebug logDebug $ showTrafficStats result
#endif

    -- We're done
    sClose connection
    where
      -- Higher-level connect function
      connect' hostname port = do
        protocol <- getProtocolNumber "tcp"
        entry <- getHostByName hostname
        sock <- Network.Socket.socket (hostFamily entry) Stream protocol
        connect sock $ SockAddrInet (fromIntegral port) $ hostAddress entry
        return sock
