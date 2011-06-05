module Ssh.ConnectionData (
    ConnectionData (..)
) where

import Data.Word

data ConnectionData = ConnectionData {
      sessionId :: [Word8]
    , sharedSecret :: [Word8]
    , exchangeHash :: [Word8]
    , client2ServerIV :: [Word8]
    , server2ClientIV :: [Word8]
    , client2ServerEncKey :: [Word8]
    , server2ClientEncKey :: [Word8]
    , client2ServerIntKey :: [Word8]
    , server2ClientIntKey :: [Word8]
}
