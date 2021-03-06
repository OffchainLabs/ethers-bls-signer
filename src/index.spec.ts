import { BlsSigner } from "./index";
import { expect } from "chai";
import "mocha";
import { concat, hexlify, randomBytes } from "ethers/lib/utils";

const randHex = (n: number) => hexlify(randomBytes(n))

describe("Ethers bls signer", () => {
  it("should instantiate signer class", async () => {
    const privateKey =
      "0xf3c577f834077e65232aefe9439dc0ebe7f0e9f723989b3f61b368707d320d08";
    const domain = randHex(32);
    const signer = await BlsSigner.getBlsSigner(privateKey, domain);
    expect(signer._isSigner).to.equal(true);
  });

  it("should sign messages correctly", async () => {
    const privateKey =
      "0x88f8223131ba22b488e060ae6af60c3a70f8a3b52299b792907672be8e18d314";
    const domain =
      "0xdffe14e8f78878d1c94ba4a209cfc08b21f23fb83974292cf8b486e315e559b1";
    const signer = await BlsSigner.getBlsSigner(privateKey, domain);
    const message = "0xaeeed5276eed0bc1799a62c6";

    const [expectedX, expectedY] = [
      "0x253fc8d778f980e48c2807bc689bda486ea34f8757f7002dd65a585f14d6ba71",
      "0x0b4bb856126bd2ca5f8ad41b45630b99530f21c342010e6fe1d34376f469648a",
    ];
    const recoveryParam = "0x1c";

    const expected = hexlify(concat([expectedX, expectedY, recoveryParam]));
    const signature = await signer.signMessage(message);
    expect(signature).to.equal(expected);
  });

  it("should recover address from public key", async () => {
    const privateKey =
      "0x88f8223131ba22b488e060ae6af60c3a70f8a3b52299b792907672be8e18d314";
    const domain =
      "0xdffe14e8f78878d1c94ba4a209cfc08b21f23fb83974292cf8b486e315e559b1";
    const signer = await BlsSigner.getBlsSigner(privateKey, domain);

    const expectedAddress = "0xeea83b9be462ba515e528faec67e16430d12871c";
    const address = await signer.getAddress();
    expect(address).to.equal(expectedAddress);
  })
});
