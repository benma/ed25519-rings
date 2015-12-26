-- |
--
-- This module implements the ed25519 signing/verifying standard.
-- http://ed25519.cr.yp.to/
-- It is a port of http://ed25519.cr.yp.to/python/ed25519.py, and not meant to be used in production.

module Ed25519
       ( sign
       , verify
       , encode'
       , publicKeyFromSeed
       , SecretKey
       , PublicKey
       , SKNonce(..)
       , Seed(..)
       , Commitment
       , hashToScalar
       ) where

import           Crypto.Hash.SHA512 (hash)
import           Curve (Point, ModL, basePoint, (.+), (.*))
import qualified Data.Binary as Bin
import qualified Data.Binary.Put as BinP
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.Monoid ((<>))
import           Data.LargeWord (Word256)
import           Encoding (encode', decodeInt256, encodeInt256, decodeInt512)

data Signature = Signature { _signatureR :: Point
                           , _signatureS :: ModL
                           }
               deriving (Show)

instance Bin.Binary Signature where
    put (Signature r s) = do
        Bin.put r
        BinP.putByteString $ encodeInt256 $ fromIntegral s
    get = error "not implemented"

type SecretKey = Word256
type PublicKey = Point

-- ed25519 commitments are 64 bytes.
-- However, we reduce it modulo L right away, as it is only ever used in this field.
type Commitment = ModL

class SKNonce a where
    createSecretKeyAndNonce :: a -> (SecretKey, BS.ByteString)

newtype Seed = Seed BS.ByteString

instance SKNonce Seed where
    -- | createSecretKeyAndNonce takes a seed and returns a secret key and a nonce seed from which
    -- one can derive deterministic nonces in signing algorithms.
    -- Per ed25519 standard, the 254th bit is set, the 255th bit is cleared, and the first three bits are cleared.
    -- The 254th and 255th bit are set to prevent timing attacks when using a bad implementation of the montgomery ladder.
    -- See http://crypto.stackexchange.com/questions/11810/when-using-curve25519-why-does-the-private-key-always-have-a-fixed-bit-at-2254/11818.
    --
    -- The lower three bits are cleared so that the secret key is a multiple of 8.
    -- This is to prevent small-subgroup attacks (http://safecurves.cr.yp.to/twist.html).
    -- The reason is that order of the curve group is 8 times larger than the curve subgroup ℤ/l,
    -- so not every point on the curve generates the curve group.
    createSecretKeyAndNonce (Seed seed) = 
        let (left, right) = BS.splitAt 32 (hash seed)
            -- set the 254th bit and clear the first three and the 255th bit.
            sk = (decodeInt256 left .|. (2^254)) .&. complement (7+2^255)
        in (fromIntegral sk, right)
    

publicKeyFromSecretKey :: SecretKey -> PublicKey
publicKeyFromSecretKey sk = fromIntegral sk .* basePoint

publicKeyFromSeed :: (SKNonce s) => s -> PublicKey
publicKeyFromSeed = publicKeyFromSecretKey . fst . createSecretKeyAndNonce

hashToScalar :: (Num a) => BS.ByteString -> a
hashToScalar = fromIntegral . decodeInt512 . hash

-- Almost (but good enough) uniform distribution modulo L.
-- See ed25519 paper.
deriveNonce :: BS.ByteString -> ModL
deriveNonce = hashToScalar 

commit :: Point -> PublicKey -> BS.ByteString -> Commitment
commit r publicKey msg = hashToScalar $ encode' r <> encode' publicKey <> msg

sign :: (SKNonce s) => s -> BS.ByteString -> Signature
sign seed msg = Signature r s
  where
    (sk, nonce) = createSecretKeyAndNonce seed
    k = deriveNonce (nonce <> msg)
    r = k .* basePoint
    pk = publicKeyFromSecretKey sk
    e = commit r pk msg
    s = k + e*fromIntegral sk

verify :: Signature -> BS.ByteString -> PublicKey -> Bool
verify (Signature r s) msg pk =
    let e = commit r pk msg
    in s .* basePoint == r .+ (e .* pk)
