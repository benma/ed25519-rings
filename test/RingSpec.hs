{-# LANGUAGE OverloadedStrings #-}

module RingSpec where

import Ed25519 (Seed(..))
import Ring
import Test.Hspec

spec :: Spec
spec = do
    describe "ring sign verify" $ do
        describe "ring size 3" $ do
            let pks = map (publicKeyFromSeed) [Seed "secret1", Seed "secret2", Seed "secret3"]
                msg = "msg"
                sig1 = sign (Seed "secret1") 0 pks msg
                sig2 = sign (Seed "secret2") 1 pks msg
                sig3 = sign (Seed "secret3") 2 pks msg
                invalidSig = sign (Seed "unknown") 0 pks msg
            it "verify" $ verify sig1 pks msg `shouldBe` True
            it "verify" $ verify sig2 pks msg `shouldBe` True
            it "verify" $ verify sig3 pks msg `shouldBe` True
            it "verify not" $ verify sig1 pks "msg2" `shouldBe` False
            it "verify not" $ verify sig1 [pks!!0] msg `shouldBe` False
            it "verify not" $ verify sig1 [pks!!0, pks!!2, pks!!1] msg `shouldBe` False
            it "verify not" $ verify invalidSig pks msg `shouldBe` False
    describe "borro" $ do
        let pks1 = map publicKeyFromSeed [Seed "r1secret1", Seed "r1secret2", Seed "r1secret3"]
            pks2 = map publicKeyFromSeed [Seed "r2secret1", Seed "r2secret2"]
            sig = borromeanSign [(Seed "r1secret1", 0), (Seed "r2secret2", 1)] [pks1, pks2] "msg"
        it "borro" $ borromeanVerify sig [pks1, pks2] "msg" `shouldBe` True
