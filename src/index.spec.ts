import { BlsSigner } from "./index"
import { randHex } from "./hubble-project/utils"
import { expect } from 'chai';
import 'mocha';

describe('Ethers bls signer', () => {
  it('should instantiate signer class', async () => {
    const privateKey = randHex(12);
    const domain = randHex(32);
    const signer = await BlsSigner.getBlsSigner(privateKey, domain);
    expect(signer._isSigner).to.equal(true);
  });
});
