{-# LANGUAGE OverloadedStrings #-}

module Ed25519Spec where

import qualified Control.Monad as M
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BSC
import           Data.Monoid ((<>))
import           Ed25519 (Seed(..), sign, verify, encode', publicKeyFromSeed)
import           System.IO (withFile, IOMode(..))
import           Test.Hspec

-- http://ed25519.cr.yp.to/python/sign.input
spec :: Spec
spec = do
    it "sign/verify" $ do
        let sig = sign (Seed "seed") "msg"
        verify sig "msg" (publicKeyFromSeed (Seed "seed")) `shouldBe` True
    
    file <- runIO $ withFile "test/sign.input" ReadMode BS.hGetContents
    let fileLines = filter (not . BS.null) $ BSC.split '\n' file
    M.forM_ (zip [1..] fileLines) $ \(num, line) -> do
        describe (show num ++ ". sign.input line") $ do
            let [seedAndPK, pkBytes, msg, sigBytes, ""] = BSC.split ':' line
                (seedAndPK', "") = B16.decode seedAndPK
                seed = Seed (BS.take 32 seedAndPK')
                derivedPK = publicKeyFromSeed seed
                (pkBytes', "") = B16.decode pkBytes
                (msg', "") = B16.decode msg
                (sigBytes', "") = B16.decode sigBytes
                sig = sign seed msg'
            it "pk derivation" $ encode' derivedPK `shouldBe` pkBytes'
            it "sign" $ encode' sig <> msg' `shouldBe` sigBytes'
            it "verify" $ verify sig msg' derivedPK `shouldBe` True
            it "verify not" $ verify sig (msg' <> "s") derivedPK `shouldBe` False
