{-# LANGUAGE OverloadedStrings #-}

module Ssh.Authentication.Password (
      passwordAuth
) where

import qualified Data.ByteString.Lazy as B

import Ssh.Transport
import Ssh.Authentication

type SshString = B.ByteString

passwordAuth = AuthenticationService "password" doAuth

doAuth :: SshString -> SshConnection Bool
doAuth username = error "DoAuth for password"

askPassword :: SshString -> IO SshString
askPassword = error "Ask user for his password!"
