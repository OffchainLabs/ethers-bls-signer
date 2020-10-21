import { BytesLike, Signer } from "ethers";
import { Bytes } from "ethers/lib/utils";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
export declare class BlsSigner extends Signer {
    readonly privateKey: () => string;
    private mclwasm;
    private constructor();
    static getBlsSigner(privateKey: BytesLike, domain: BytesLike): Promise<BlsSigner>;
    signMessage: (message: Bytes | string) => Promise<string>;
    getAddress: () => Promise<string>;
    signTransaction: (transaction: TransactionRequest) => Promise<string>;
    connect: (provider: Provider) => Signer;
    private getKeyPair;
    private getSecret;
    private addressFromPublicKey;
}
