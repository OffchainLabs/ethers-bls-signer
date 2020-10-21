import { BytesLike, Signer } from "ethers";
import {
  hexlify,
  concat,
  Bytes,
  resolveProperties,
  hexZeroPad,
  joinSignature,
} from "ethers/lib/utils";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import * as mcl from "@thehubbleproject/bls/dist/mcl";
import { serialize, UnsignedTransaction } from "@ethersproject/transactions";
import { keccak256 } from "@ethersproject/keccak256";

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
    const [x, y] = mcl.g1ToHex(signature);

    const payload = joinSignature({
      r: hexZeroPad(x, 32),
      s: hexZeroPad(y, 32),
      recoveryParam: 27,
    });

    return Promise.resolve(payload);
  };
  getAddress = (): Promise<string> => {
    const { pubkey } = this.getKeyPair(this.privateKey());
    return Promise.resolve(this.addressFromPublicKey(pubkey));
  };

  signTransaction = (transaction: TransactionRequest): Promise<string> => {
    return resolveProperties(transaction).then((tx) => {
      // https://github.com/ethers-io/ethers.js/blob/be4e2164e64dfa0697561763e8079120a485a566/packages/wallet/src.ts/index.ts#L110-L115
      if (tx.from != null) {
        const address = this.addressFromPublicKey(
          this.getKeyPair(this.privateKey()).pubkey
        );
        if (tx.from !== address) {
          // console.error(
          //   "transaction from address mismatch",
          //   "transaction.from",
          //   transaction.from
          // );
        }
        delete tx.from;
      }
      const signature = this.signMessage(
        keccak256(serialize(<UnsignedTransaction>tx))
      );
      return signature.then((value) =>
        serialize(<UnsignedTransaction>tx, value)
      );
    });
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

  private addressFromPublicKey = (pubkey: mcl.PublicKey): string => {
    // TODO: does the public key need padding before being hashed?
    const payload = keccak256(
      concat([
        hexZeroPad(pubkey[0], 32),
        hexZeroPad(pubkey[1], 32),
        hexZeroPad(pubkey[2], 32),
        hexZeroPad(pubkey[3], 32),
      ])
    );
    // return resolves to last 20 bytes of hashed public key
    return "0x" + payload.slice(payload.length - 40);
  };
}
