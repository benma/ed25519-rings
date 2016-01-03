{-# LANGUAGE OverloadedStrings #-}

module ZKPSpec where

import qualified Control.Monad as M
import           Curve (isOnCurveSubgroup)
import           Test.Hspec
import           ZKP (otherGenerator, createRangeProof, verifyRangeProof)

spec :: Spec
spec = do
    it "otherGenerator is on the curve subgroup" $
        isOnCurveSubgroup otherGenerator `shouldBe` True
    describe "zkp" $ do
        let bits = 3
        M.forM_ [0..2^bits] $ \amount -> do
            it ("zkp " ++ show amount) $ do
                let proof = createRangeProof "seed" bits amount
                verifyRangeProof proof `shouldBe` True
