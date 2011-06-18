{-# LANGUAGE OverloadedStrings #-}

-- | Handles everything related to a remote shell. Needs to be done asynchronously because we have to wait for both local actions (keypresses) and remote actions
module Ssh.Channel.Session.Shell (
      requestShell
) where

import Data.Binary.Get
import Data.Binary.Put

import Control.Concurrent

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B

import Ssh.Packet
import Ssh.Channel
import Ssh.String
import Ssh.Transport
import Ssh.NetworkIO
import Ssh.Debug

-- | Request a remote shell on the channel. The MVar will contain the connection for this channel, which will be at all gotten/put in the MVar by the caller of this!
requestShell :: MVar (SshConnection ()) -> Channel ChannelInfo
requestShell connection = do
    -- Request a shell on this channel
    nr <- getLocalChannelNr
    let request = ChannelRequest nr "shell" False ""
    MS.lift $ sPutPacket request

    -- Update the channel info
    setChannelHandler $ handleShellRequest connection

-- | Handle a shell request
handleShellRequest :: MVar (SshConnection ()) -> SshString -> Channel ChannelInfo
handleShellRequest connection payload = error "Meh"
