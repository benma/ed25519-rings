-- |
--
-- This module implements Abe-Ohkubo-Suzuki ring signatures over ed25519.
-- https://github.com/Blockstream/borromean_paper

module Ring
       ( sign
       , verify
       , publicKeyFromSeed
       , BorromeanSignature(..)
       , borromeanSign
       , borromeanVerify
       , deriveNonce
       ) where

import qualified Control.Monad as M
import           Crypto.Hash.SHA512 (hash)
import           Curve (Point, ModL, basePoint, (.+), (.*))
import qualified Data.Binary as Bin
import qualified Data.Binary.Put as BinP
import qualified Data.ByteString as BS
import           Data.Monoid ((<>))
import           Ed25519 (SecretKey, PublicKey, SKNonce, createSecretKeyAndNonce, publicKeyFromSeed, hashToScalar)
import           Encoding (encode', encodeInt256)

type S = ModL

-- The borromean paper suggests 256 bits for the commitment.
-- However, we reduce it modulo L right away, as it is only ever used in this field.
type Commitment = ModL

data Signature = Signature Commitment [S]

instance Bin.Binary Signature where
    put (Signature e ss) = do
        BinP.putByteString $ encodeInt256 $ fromIntegral e
        M.forM_ ss (BinP.putByteString . encodeInt256 . fromIntegral)
    get = error "not implemented"

-- Almost (but good enough) uniform distribution modulo L.
-- See ed25519 paper.
deriveNonce :: BS.ByteString -> Int -> ModL
deriveNonce nonce i = hashToScalar (nonce <> encodeInt256 (fromIntegral i))

getCommonCommit :: [PublicKey] -> BS.ByteString -> BS.ByteString
getCommonCommit pks msg = hash $ BS.concat (map encode' pks) <> msg

commit :: BS.ByteString -> Point -> Commitment
commit prefix r = hashToScalar $ prefix <> encode' r

ringE :: BS.ByteString -> Commitment -> [S] -> [PublicKey] -> Commitment
ringE commitPrefix e0 ss pks = foldr next e0 (zip ss pks)
  where
    next :: (S, PublicKey) -> Commitment -> Commitment
    next (s_j, pk_j) e_j =
        let r_j = (s_j .* basePoint) .+ ((-e_j) .* pk_j)
            eNext = commit commitPrefix r_j
        in eNext

data RingData = RingData
                { _commitPrefix :: BS.ByteString
                , _sk :: SecretKey
                , _k :: ModL
                , _pksLeft :: [PublicKey] -- pksLeft the pks left of the pk belonging to sk.
                , _pksRight :: [PublicKey] -- pksRight are the pks right of the pk belonging to sk.
                , _ssLeft :: [S] -- One random s value for every pk.
                , _ssRight :: [S] -- One random s value for every pk.
                }

makeRingData :: (SKNonce s) => BS.ByteString -> s -> Int -> [PublicKey] -> RingData
makeRingData commitPrefix seed pkIndex pks =
    RingData
    { _commitPrefix = commitPrefix
    , _sk = sk
    , _k = getNonce 0
    , _pksLeft = pksLeft
    , _pksRight = pksRight
    , _ssLeft = map getNonce [1..pkIndex]
    , _ssRight = map getNonce [pkIndex+1..pkIndex+length pksRight]
    }
  where
    (sk, nonce) = createSecretKeyAndNonce seed
    getNonce = deriveNonce (nonce <> commitPrefix)
    (pksLeft, (_:pksRight)) = splitAt pkIndex pks

commitLeft :: RingData -> Commitment
commitLeft ringData = ringE commitPrefix eStart ssLeft pksLeft
  where
    commitPrefix = _commitPrefix ringData
    (ssLeft, pksLeft) = (_ssLeft ringData, _pksLeft ringData)
    rStart = _k ringData .*  basePoint
    eStart = commit commitPrefix rStart

commitRight :: Commitment -> RingData -> Commitment
commitRight eStart ringData = ringE commitPrefix eStart ssRight pksRight
  where
    commitPrefix = _commitPrefix ringData
    (ssRight, pksRight) = (_ssRight ringData, _pksRight ringData)

tie :: Commitment -> RingData -> S
tie eStart ringData = s_i
  where
    sk = _sk ringData
    k_i = _k ringData
    e_i = commitRight eStart ringData
    -- now (r_j=s_j*B-e_j*PK) holds for all j!=i
    -- (all pks but the one which belongs to sk).
    -- To make the equation fit (with a fixed commitment e_i),
    -- we need the secret key.
    s_i = k_i + e_i * fromIntegral sk

sign :: (SKNonce s)
     => s
     -> Int
     -> [PublicKey]
     -> BS.ByteString
     -> Signature
sign seed pkIndex pks msg = Signature e_0 (ssLeft ++ [s_i] ++ ssRight)
  where
    commitPrefix = getCommonCommit pks msg
    ringData = makeRingData commitPrefix seed pkIndex pks
    e_0 = commitLeft ringData
    s_i = tie e_0 ringData
    (ssLeft, ssRight) = (_ssLeft ringData, _ssRight ringData)

verify :: Signature -> [PublicKey] -> BS.ByteString -> Bool
verify (Signature e_0 ss) pks msg = e_0 == e
  where
    commitPrefix = getCommonCommit pks msg
    e = ringE commitPrefix e_0 ss pks


data BorromeanSignature = BorromeanSignature Commitment [[S]]
                        deriving (Show)

commitMany :: [Commitment] -> Commitment
commitMany = hashToScalar . BS.concat . map (encodeInt256 . fromIntegral)
    
borromeanSign :: (SKNonce s)
              => [(s, Int)]
              -> [[PublicKey]]
              -> BS.ByteString
              -> BorromeanSignature
borromeanSign rings lpks msg = BorromeanSignature e_0_all ss
  where
    commitPrefix = getCommonCommit (concat lpks) msg
    ringDatas = [ makeRingData commitPrefix seed pkIndex pks
                | ((seed, pkIndex), pks) <- zip rings lpks
                ]
    e_0 = map commitLeft ringDatas
    e_0_all = commitMany e_0
    ss = [ _ssLeft ringData ++ [s_i] ++ _ssRight ringData
         | ringData <- ringDatas
         , let s_i = tie e_0_all ringData
         ]

borromeanVerify :: BorromeanSignature -> [[PublicKey]] -> BS.ByteString -> Bool
borromeanVerify (BorromeanSignature eStart lss) lpks msg =
    eStart == commitMany e
  where
    commitPrefix = getCommonCommit (concat lpks) msg
    e = [ ringE commitPrefix eStart ss pks
        | (ss, pks) <- zip lss lpks
        ]
