-- | We use a lazy bytestring everywhere as standard string type
module Ssh.String (
      SshString
    , unpackToString
) where

import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy.Char8 () -- IsString instance for the above

type SshString = B.ByteString

-- | Convert a ByteString of Word8 to a regular String
unpackToString s = map (toEnum . fromEnum) $ B.unpack s
