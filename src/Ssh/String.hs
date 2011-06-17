-- | We use a lazy bytestring everywhere as standard string type
module Ssh.String (
      SshString
) where

import qualified Data.ByteString.Lazy as B

type SshString = B.ByteString
