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
import Ssh.HostKeyAlgorithm
import Ssh.HostKeyAlgorithm.HostsFile
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
    , port :: Maybe Int
} deriving Show

defaultOptions = Options Nothing Nothing

options :: [OptDescr (Options -> Options)]
options = [
      Option [] ["privatekeyfile"] (OptArg ((\f opts -> opts { privateKeyFile = Just f }) . fromMaybe "") "file") "Location of the (DSA) private key file to use, if any"
    , Option ['p'] ["port"] (OptArg ((\p opts -> opts { port = Just $ read p } ) . fromMaybe "") "port") "Port to connect to"
  ]

-- | Result: first are the options, second should be the 'non-option' user@hostname
getOptions :: [String] -> IO (Options, [String])
getOptions argv =
    case getOpt Permute options argv of
        -- (_,[],_)   -> ioError (userError ("No hostname specified!\n" ++ (usageInfo header options))) -- TODO: uncomment this in the final code, makes sure the user gave a hostname :)
        (o,n,[]  ) -> return  (foldl (flip id) defaultOptions o, n)
        (_,_,errs) -> ioError (userError (concat errs ++ usageInfo header options))
    where header = "Usage: SshClient [OPTIONS...] [user@]hostname"

clientVersion = "SSH-2.0-BartSSHaskell-0.0.1 This is crappy software!\r\n"

clientCryptos = [
      (CryptionAlgorithm "aes256-ctr" (ctrAesEncrypt 256) (ctrAesDecrypt 256) 16),
      (CryptionAlgorithm "aes256-cbc" (cbcAesEncrypt 256) (cbcAesDecrypt 256) 16)
    ]

clientHashMacs = [ sha1HashMac ]

rsaHostKey = PublicKeyAlgorithm "ssh-rsa" (error "RSA HOSTKEY") (error "RSA HOSTKEY") (error "RSA HOSTKEY")

clientHostKeys = [rsaHostKey]

serverHostKeyAlgos = [ HostKeyAlgorithm "ssh-dss" (checkHostKeyInFile rawDSSVerifier) rawDSSVerifier ]

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
--   Returns (username, hostname, hostnameString). Since we first resolve the hostname, that's a regular 'String', since we'll send the username, that's an 'SshString'.
getUserAndHostNameFromArguments :: Maybe String -> IO (SshString, String)
getUserAndHostNameFromArguments arg = do
    if isNothing arg || arg == Just "localhost"
        then return ("bartcopp", "localhost")
        else parseUserAndHostName $ fromJust arg

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
clientLoop :: SshString -> SshString -> Options -> Maybe String -> ConnectionData -> SshConnection ()
clientLoop username hostname options mCommand cd = do
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

    -- Depending on the extra options given on the command line, open a remote shell, or execute a command remotely
    let action = case mCommand of
            Nothing      -> doShell ti
            Just command -> execRemote $ B.pack $ map (toEnum . fromEnum) command

    -- Perform the user-specified action on this channel
    runGlobalChannelsToConnection initialGlobalChannelsState action

    where
      execRemote command = do -- execute a command remotely, and show the result
        channel <- openChannel sessionHandler ""                -- Open a channel
        insertChannel channel $ requestExec command             -- Request Exec
        loop -- Loop
            where
                loop :: Channels ()
                loop = do
                    packet <- MS.lift $ sGetPacket
                    handleChannel packet

                    globalInfo <- MS.get
                    continueOrExit globalInfo loop

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
                loop :: MVar (GlobalChannelInfo, SshTransportInfo) -> SshSocket -> Channels ()
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

                    -- Try to handle lower levels of packets
                    handledPacket <- MS.lift $ handlePacket connection packet

                    -- If we handled the packet at a lower level, we won't process it again, otherwise it might be a channel packet
                    if handledPacket
                        then return ()
                        else handleChannel packet >> return ()

                    -- Maybe it is time to start rekeying!
                    newHandler <- MS.lift $ checkToRekey connection
                    MS.lift $ MS.modify $ \c -> c { handlePacket = newHandler }

                    -- Put back the changed state
                    globalInfo' <- MS.get
                    connection' <- MS.lift $ MS.get
                    MS.liftIO $ putMVar safeInfo (globalInfo', connection')

                    continueOrExit globalInfo' $ loop safeInfo sshSocket

      -- We opened a channel in our client loop. If 0 channels are in use, this means we/the server closed all our channel(s)
      -- => terminate our loop; otherwise => keep running
      continueOrExit globalInfo loopAction =
        case Map.size $ usedChannels globalInfo of
            0         -> return ()
            otherwise -> loopAction

      -- A check to see if we should rekey, and if we should do it: actually send a message to start it
      checkToRekey connection =
        if False -- TODO renable bytes > 750 && canRekey -- For now: a pretty low number to debug it. TODO: use the right values from the RFC
          then do
            printDebugLifted logDebug $ "Already " ++ show bytes ++ " bytes sent, starting a rekey"
            startRekey clientKEXAlgos serverHostKeyAlgos clientCryptos clientCryptos clientHashMacs clientHashMacs
          else
            return $ handlePacket connection
        where
          bytes = totalBytes . c2sStats $ connection -- TODO: since last (re)key instead of since beginning
          canRekey = not $ isRekeying connection -- We don't want to initiate a rekey when we are currently already rekeying!

handlePackets :: Packet -> SshConnection Bool
handlePackets (Ignore s) = printDebugLifted logDebug "Got a packet 'Ignore', and we print this message" >> return True
handlePackets _          = return False

main :: IO ()
main = do
    -- Parse the arguments
    args    <- getArgs
    (options, moreargs) <- getOptions args

    -- Get username and hostname
    -- The first non-option argument (if it exists, if it doesn't -> DEBUGGING localhist) is the location
    -- If there are extra arguments given after the location, these can be used for, for example, executing a remote command
    let (hostArgs, extraArgs) = case moreargs of
            []   -> (Nothing, Nothing)
            h:hs -> (Just h, listToMaybe hs)
    (username, hostname) <- getUserAndHostNameFromArguments hostArgs

    let portNr = fromMaybe 22 $ port options
        hostnameString = case port options of
            Nothing -> hostname
            Just p  -> hostname ++ ":" ++ show p

    -- Connect to the server
    connection <- connect' hostname portNr
    --hSetBuffering connection $ BlockBuffering Nothing

    -- Get the server's version string, send our version string
    serverVersion <- getServerVersionString connection
    printDebug logLowLevelDebug $ show serverVersion
    sendAll connection clientVersion

    -- TODO remove runState!
    -- Do the Key Exchange, initialize the SshConnection
    sshSock <- mkSocket connection

    let tinfo = mkTransportInfo sshSock hostnameString (error "HostKeyAlgo") (error "Client2ServerTransport") [] 0 (error "Server2ClientTransport") [] 0 Nothing handlePackets clientVersion serverVersion

    (cd, newState) <- flip MS.runStateT tinfo $
        doKex clientKEXAlgos serverHostKeyAlgos clientCryptos clientCryptos clientHashMacs clientHashMacs

    -- Run the client loop, i.e. the real part
    result <- MS.execStateT (clientLoop username (B.pack $ map (toEnum . fromEnum) $ hostname) options extraArgs cd) newState

    -- We might be being verbose, perhaps print out some statistics on the connection
    printDebug logDebug $ showTrafficStats result

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
