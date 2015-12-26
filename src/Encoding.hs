module Encoding
       ( encode'
       , decode'
       , encodeInt256
       , decodeInt256
       , decodeInt512
       , Word256
       , Word512
       ) where

import           Data.Binary (Binary, encode, decode)
import qualified Data.ByteString as BS
import           Data.ByteString.Lazy (toStrict, fromStrict)
import           Data.LargeWord (Word256, LargeKey)

type Word512 = LargeKey Word256 Word256

decode' :: Binary a => BS.ByteString -> a
decode' = decode . fromStrict

encode' :: Binary a => a -> BS.ByteString
encode' = toStrict . encode

decodeInt256 :: BS.ByteString -> Word256
decodeInt256 bs = case BS.length bs of
    32 -> decode' (BS.reverse bs)
    _ -> error "bytestring should be 32 bytes"

encodeInt256 :: Word256 -> BS.ByteString
encodeInt256 = BS.reverse . encode'

decodeInt512 :: BS.ByteString -> Word512
decodeInt512 bs = case BS.length bs of
    64 -> decode' (BS.reverse bs)
    _ -> error "bytestring should be 64 bytes"
