{-# LANGUAGE OverloadedStrings #-}

module Ssh.Authentication.Password (
      passwordAuth
) where

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B
import Network.Socket (Socket, SockAddr (..), SocketType (..), socket, connect)
import Data.Binary.Put
import Control.Monad

-- TODO: make portable?
import System.Posix.IO
import System.Posix.Terminal

import Ssh.Packet
import Ssh.NetworkIO
import Ssh.Transport
import Ssh.Authentication

type SshString = B.ByteString

passwordAuth = AuthenticationService "password" doAuth

userAuthPayload :: SshString -> SshString
userAuthPayload pwd = runPut $ do -- pws should be UTF-8 encoded!
    putBool False -- no new password stuff yet
    putString pwd

-- TODO: password authentication SHOULD be disabled when no confidentiality (cipher == none) or no mac are used!
-- TODO: handle SSH_MSG_USERAUTH_PASSWD_CHANGEREQ?
doAuth :: Socket -> SshString -> SshString -> SshConnection Bool
doAuth socket username servicename = do
    transportInfo <- MS.get
    pwd <- MS.liftIO $ askPassword username
    let payload = userAuthPayload pwd
        c2s = client2server transportInfo
        s2c = server2client transportInfo
    sPutPacket c2s socket $ UserAuthRequest username servicename "password" payload
    response <- sGetPacket s2c socket
    return $ case response of
        UserAuthSuccess -> True
        _               -> False

hostName = "hostname" -- TODO

askPassword :: SshString -> IO SshString
askPassword username = do
    let userLocation = B.append username $ B.append "@" hostName
    putStrLn $ "Password for " ++ (map (toEnum . fromEnum) $ B.unpack userLocation) ++ ":"
    -- Echo Off, so we can enter our password
    attrs <- getTerminalAttributes stdInput
    setTerminalAttributes stdInput (withoutMode attrs EnableEcho) Immediately
    -- Read password
    pwd <- (B.pack . map (toEnum . fromEnum)) `liftM` getLine -- UTF8?
    -- Reset terminal
    setTerminalAttributes stdInput attrs Immediately
    return pwd
