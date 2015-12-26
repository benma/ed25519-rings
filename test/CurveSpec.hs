module CurveSpec where

import Curve (Point(..), basePoint, isOnCurve, (.*))
import Test.Hspec
import Data.Binary (encode, decode)

spec :: Spec
spec = do
    it "onCurve" $ isOnCurve basePoint `shouldBe` True
    describe "encoding" $ do
        describe "even x" $ do
            it "is even" $ let Point x _ = basePoint in even (toInteger x) `shouldBe` True
            it "encdec" $ decode (encode basePoint) `shouldBe` basePoint
        describe "odd x" $ do
            let point = 123 .* basePoint
            it "is odd" $ let Point x _ = point in odd (toInteger x) `shouldBe` True
            it "encdec" $ decode (encode point) `shouldBe` point
    it "onCurve" $ isOnCurve basePoint `shouldBe` True
