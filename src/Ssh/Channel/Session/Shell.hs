{-# LANGUAGE OverloadedStrings #-}

-- | Handles everything related to a remote shell. Needs to be done asynchronously because we have to wait for both local actions (keypresses) and remote actions
module Ssh.Channel.Session.Shell (
      requestShell
) where

import Data.Binary.Get
import Data.Binary.Put

import Control.Concurrent
import Data.Maybe
import Data.Word

import System.Posix.IO
import qualified System.Posix.Terminal as Term

import qualified Control.Monad.State as MS
import qualified Data.ByteString.Lazy as B
import qualified Data.Map as Map

import Ssh.Packet
import Ssh.Channel
import Ssh.String
import Ssh.Transport
import Ssh.NetworkIO
import Ssh.Debug

-- | Opcodes for Terminal Modes
data TerminalMode =
      TEnd  -- ^ 0, End of list of opcodes

-- | Info about the terminal for a pseudo-terminal request
data Terminal = Terminal {
      termValue :: SshString
    , widthChars :: Int
    , heightChars :: Int
    , widthPixels :: Int
    , heightPixels :: Int
    , terminalModes :: [TerminalMode]
}

-- | Maps a terminal mode to its opcode, as per RFC 4254, p 19, Section 8 (SSH Connection Protocol: Encoding of Terminal Modes)
mapTerminalModeToOpcode :: TerminalMode -> Word8
mapTerminalModeToOpcode TEnd = 0

-- | Put instance for a list of encoded 'TerminalMode's, encoded as a string
terminalModesString :: [TerminalMode] -> Put
terminalModesString l = putString $ B.pack $ map mapTerminalModeToOpcode l

-- | Put instance to encode a 'Terminal'
putTerminal :: Terminal -> Put
putTerminal (Terminal term wC hC wP hP tm) = do
    putString term
    putWord32 $ (toEnum . fromEnum) wC
    putWord32 $ (toEnum . fromEnum) hC
    putWord32 $ (toEnum . fromEnum) wP
    putWord32 $ (toEnum . fromEnum) hP
    terminalModesString tm

-- TODO: get actual data from the environment
-- | Gets the current terminal info, and add the specified modes to it
getTerminalInfo :: [TerminalMode] -> IO Terminal
getTerminalInfo modes = return $ Terminal "vt100" 80 24 640 480 modes


-- | Iterate 'withoutMode' on a list
withoutModes :: Term.TerminalAttributes -> [Term.TerminalMode] -> Term.TerminalAttributes
withoutModes = foldl Term.withoutMode

-- | Set terminal modes so we can function as a remote shell: echo off and so
setTerminalModesStart :: IO ()
setTerminalModesStart = do

    attrs <- Term.getTerminalAttributes stdInput

    let withouts = [    -- Don't echo stuff
                        Term.EnableEcho
                        -- Flow control thingies: IXOFF, IXON, IXANY
                        , Term.StartStopInput
                        , Term.StartStopOutput
                        -- Pass on keyboard interrupts (ctrl+c and so)
                        , Term.KeyboardInterrupts
                   ]
    Term.setTerminalAttributes stdInput (withoutModes attrs withouts) Term.Immediately

-- | Request a remote shell on the channel.
--   The MVar will contain the global 'Channels' data for this channel. Whenever *anyone* (either this code, or the caller of 'requestShell') wants to communicate
--   with the server, the MVar should be used! This is so we can update the 'ChannelInfo's window size etc. safely after sending packets,
--   and to send data in a serialized way.
requestShell :: MVar (GlobalChannelInfo, SshTransportInfo) -> Channel ChannelInfo
requestShell minfo = do
    -- Request a shell on this channel
    nr <- getLocalChannelNr

    -- First of all, request a PTY to begin with
    term <- MS.liftIO $ getTerminalInfo [TEnd]
    let ptyReq = ChannelRequest nr "pty-req" False $ runPut $ putTerminal term
    MS.lift $ sPutPacket ptyReq

    -- Now request a shell
    let shellReq = ChannelRequest nr "shell" False ""
    MS.lift $ sPutPacket shellReq

    -- Set the terminal modes (TODO: unset them again??)
    MS.liftIO setTerminalModesStart

    -- Update the channel info
    info <- setChannelHandler $ handleShellRequest minfo

    MS.liftIO $ forkIO $ shellReadClientLoop nr minfo

    return info

-- | The main loop. Wait for the user to write data on standard input, and send that over
--   Since we queue the data, 'Channel' will automatically queue our data, and send it over once the channel has been set up and the window size large enough.
shellReadClientLoop :: Int -> MVar (GlobalChannelInfo, SshTransportInfo) -> IO ()
shellReadClientLoop channelId channelsLock = do
    -- Sleep until the user enters something on standard input:
    (byte, nrRead) <- fdRead stdInput 1

    -- We're going to send this byte! So first of all, lock the state
    (globalInfo, transport) <- MS.liftIO $ takeMVar channelsLock

    -- Which channel is this again?
    let channelInfo = fromJust $ Map.lookup channelId (usedChannels globalInfo)

    -- Send the byte encoded to the server
    let packedData  = runPut $ putString $ B.pack $ map (toEnum . fromEnum) byte                  -- Pack the data to be sent

    let globalInfoAction = MS.execStateT (queueDataOverChannel packedData channelInfo) globalInfo -- SshConnection action updating/returning the new globalInfo
    (globalInfo', transport') <- MS.runStateT globalInfoAction transport                          -- Get the new transport state and globalInfo

    -- We're done, put/unlock the (new) state
    putMVar channelsLock (globalInfo', transport')

    -- Loop!
    shellReadClientLoop channelId channelsLock

-- | Handle a shell request: currently just print it out to standard output
handleShellRequest :: MVar (GlobalChannelInfo, SshTransportInfo) -> SshString -> Channel ChannelInfo
handleShellRequest channelsLock payload = do
    --printDebugLifted logDebug "This is the result of a shell request:"
    let raw = B.unpack payload
    MS.liftIO $ putStr $ map (toEnum . fromEnum) raw
    MS.get >>= return

