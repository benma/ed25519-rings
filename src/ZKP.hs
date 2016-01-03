{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE OverloadedStrings #-}

module ZKP
       ( otherGenerator
       , createRangeProof
       , verifyRangeProof
       ) where

import qualified Crypto.Hash.SHA256 as SHA256
import           Crypto.Hash.SHA512 (hash)
import           Curve (Point, ModL, basePoint, (.*), (.+))
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.Int (Int64)
import           Ed25519 (SKNonce(..), SecretKey, PublicKey)
import           Encoding (encode', decode', encodeInt256)
import           Ring (BorromeanSignature, borromeanSign, borromeanVerify, deriveNonce)

-- otherGenerator is a random generator of the curve subgroup.
-- No one knows k in k*basePoint=otherGenerator.
otherGenerator :: Point
otherGenerator = decode' . SHA256.hash . SHA256.hash . SHA256.hash . SHA256.hash . SHA256.hash . SHA256.hash . SHA256.hash . SHA256.hash . encode' $ basePoint

pedersenCommitment :: ModL -> Int64 -> Point
pedersenCommitment blinding amount = (blinding .* basePoint) .+ (fromIntegral amount .* otherGenerator)

data CanonicalSKNonce = CanonicalSKNonce SecretKey BS.ByteString

instance SKNonce CanonicalSKNonce where
    createSecretKeyAndNonce (CanonicalSKNonce sk nonce) = (sk, nonce)

-- Create proof that amount is in [0, 2^Bits].
createRangeProof :: BS.ByteString -> Int -> Int64 -> ([Point], BorromeanSignature)
createRangeProof seed bits amount = (commitments, borromeanSign sks (pksFromCommitments commitments) "")
    where
      (seed1, seed2) = BS.splitAt 32 (hash seed)
      -- blindingFactors are random but sum up to 0.
      blindingFactors = let factors = map (deriveNonce seed1) [0..bits-2]
                        in - sum factors : factors
      commitments = [pedersenCommitment blinding (amount .&. (2^i)) | (i, blinding) <- zip [0..] blindingFactors]
      sks = [(CanonicalSKNonce sk nonce, index)
            | (i, blinding) <- zip [0..] blindingFactors
            , let isSet = amount .&. (2^i) == 2^i
                  index = if isSet then 0 else 1
                  sk = fromIntegral blinding
                  nonce = seed2 `BS.append` encodeInt256 (fromIntegral i)
            ]

verifyRangeProof :: ([Point], BorromeanSignature) -> Bool
verifyRangeProof (commitments, sig) = borromeanVerify sig (pksFromCommitments commitments) ""

pksFromCommitments :: [Point] -> [[PublicKey]]
pksFromCommitments commitments =
    [[ commitment .+ ((fromIntegral (-2^i)) .* otherGenerator)
     , commitment
     ] | (i, commitment)  <- zip [0..] commitments]
