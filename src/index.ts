import { BytesLike, Signer } from "ethers";
import {
    hexlify,
    concat,
    Bytes,
} from "ethers/lib/utils";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import * as mcl from "./hubble-project/mcl";
const mclwasm = require("mcl-wasm");

const getKeyPair = (key: BytesLike): mcl.keyPair => {
    const secret: mcl.SecretKey = getSecret(key.toString());
    const mclPubkey: mcl.PublicKey = mclwasm.mul(mcl.g2(), secret);
    const normalized = mclwasm.normalize(mclPubkey);
    // uint256[4]
    const pubkey = mcl.g2ToHex(normalized);
    return { pubkey, secret };
};

const getSecret = (key: string): mcl.SecretKey => {
    const hexKey = hexlify(key);
    if(hexKey.length !== 66) {
        throw new Error("BLS private key should be 32 bytes. Did you include 0x at the start?");
    }
    const fr = mclwasm.deserializeHexStrToFr(key.substr(2))
    // const answer = fr.serializeToHexStr()
    return fr;
};

export class BlsSigner extends Signer {
    readonly privateKey: () => string;

    private constructor(privateKey: BytesLike) {
        super();
        this.privateKey = () => hexlify(privateKey);
    }

    public static async getBlsSigner(privateKey: BytesLike, domain: BytesLike) {
        mcl.setDomainHex(hexlify(domain));
        await mcl.init();
        return new BlsSigner(privateKey);
    }

    signMessage = (message: Bytes | string): Promise<string> => {
        const { secret } = getKeyPair(this.privateKey());
        //  signature: uint256[2]
        //  message: uint256[2]
        const digest = hexlify(message);
        const { signature, M } = mcl.sign(digest, secret);
        const payload = hexlify(concat(mcl.g1ToHex(signature)))
        // TODO: a string is not returned from the promise, this abuses the underlying `any` type
        return new Promise(resolve => resolve(payload));
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
}
