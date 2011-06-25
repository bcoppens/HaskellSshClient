-- | We use a lazy bytestring everywhere as standard string type
module Ssh.String (
      SshString
) where

import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy.Char8 () -- IsString instance for the above

type SshString = B.ByteString
