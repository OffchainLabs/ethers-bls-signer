import { BytesLike, Signer } from "ethers";
import { hexlify, concat, Bytes } from "ethers/lib/utils";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import * as mcl from "hubble-contracts/dist/ts/mcl";

export class BlsSigner extends Signer {
  readonly privateKey: () => string;
  private mclwasm: any;

  private constructor(privateKey: BytesLike) {
    super();
    this.privateKey = () => hexlify(privateKey);
    this.mclwasm = mcl.getMclInstance();
  }

  public static async getBlsSigner(privateKey: BytesLike, domain: BytesLike) {
    mcl.setDomainHex(hexlify(domain));
    await mcl.init();
    return new BlsSigner(privateKey);
  }

  signMessage = (message: Bytes | string): Promise<string> => {
    const { secret } = this.getKeyPair(this.privateKey());
    const digest = hexlify(message);
    const { signature, M } = mcl.sign(digest, secret);
    const payload = hexlify(concat(mcl.g1ToHex(signature)));
    return new Promise((resolve) => resolve(payload));
  };
  getAddress = (): Promise<string> => {
    return new Promise((resolve, reject) => reject("Not implemented"));
  };
  signTransaction = (transaction: TransactionRequest): Promise<string> => {
    return new Promise((resolve, reject) => reject("Not implemented"));
  };
  connect = (provider: Provider): Signer => {
    throw new Error("Not implemented");
  };

  private getKeyPair = (key: BytesLike): mcl.keyPair => {
    const secret: mcl.SecretKey = this.getSecret(key.toString());
    const mclPubkey: mcl.PublicKey = this.mclwasm.mul(mcl.g2(), secret);
    // TODO: do we need to normalise?
    const normalized = this.mclwasm.normalize(mclPubkey);
    const pubkey = mcl.g2ToHex(normalized);
    return { pubkey, secret };
  };
  
  private getSecret = (key: string): mcl.SecretKey => {
    const hexKey = hexlify(key);
    if (hexKey.length !== 66) {
      throw new Error(
        "BLS private key should be 32 bytes. Did you include 0x at the start?"
      );
    }
    const fr = this.mclwasm.deserializeHexStrToFr(key.slice(2));
    // console.log(fr.serializeToHexStr())
    return fr;
  };
}
