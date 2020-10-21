"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BlsSigner = void 0;
const ethers_1 = require("ethers");
const utils_1 = require("ethers/lib/utils");
const mcl = __importStar(require("@thehubbleproject/bls/dist/mcl"));
const transactions_1 = require("@ethersproject/transactions");
const keccak256_1 = require("@ethersproject/keccak256");
class BlsSigner extends ethers_1.Signer {
    constructor(privateKey) {
        super();
        this.signMessage = (message) => {
            const { secret } = this.getKeyPair(this.privateKey());
            const digest = utils_1.hexlify(message);
            const { signature, M } = mcl.sign(digest, secret);
            const [x, y] = mcl.g1ToHex(signature);
            const payload = utils_1.joinSignature({
                r: utils_1.hexZeroPad(x, 32),
                s: utils_1.hexZeroPad(y, 32),
                recoveryParam: 27,
            });
            return Promise.resolve(payload);
        };
        this.getAddress = () => {
            const { pubkey } = this.getKeyPair(this.privateKey());
            return Promise.resolve(this.addressFromPublicKey(pubkey));
        };
        this.signTransaction = (transaction) => {
            return utils_1.resolveProperties(transaction).then((tx) => {
                // https://github.com/ethers-io/ethers.js/blob/be4e2164e64dfa0697561763e8079120a485a566/packages/wallet/src.ts/index.ts#L110-L115
                if (tx.from != null) {
                    const address = this.addressFromPublicKey(this.getKeyPair(this.privateKey()).pubkey);
                    if (tx.from !== address) {
                        // console.error(
                        //   "transaction from address mismatch",
                        //   "transaction.from",
                        //   transaction.from
                        // );
                    }
                    delete tx.from;
                }
                const signature = this.signMessage(keccak256_1.keccak256(transactions_1.serialize(tx)));
                return signature.then((value) => transactions_1.serialize(tx, value));
            });
        };
        this.connect = (provider) => {
            throw new Error("Not implemented");
        };
        this.getKeyPair = (key) => {
            const secret = this.getSecret(key.toString());
            const mclPubkey = this.mclwasm.mul(mcl.g2(), secret);
            // TODO: do we need to normalise?
            const normalized = this.mclwasm.normalize(mclPubkey);
            const pubkey = mcl.g2ToHex(normalized);
            return { pubkey, secret };
        };
        this.getSecret = (key) => {
            const hexKey = utils_1.hexlify(key);
            if (hexKey.length !== 66) {
                throw new Error("BLS private key should be 32 bytes. Did you include 0x at the start?");
            }
            const fr = this.mclwasm.deserializeHexStrToFr(key.slice(2));
            // console.log(fr.serializeToHexStr())
            return fr;
        };
        this.addressFromPublicKey = (pubkey) => {
            // TODO: does the public key need padding before being hashed?
            const payload = keccak256_1.keccak256(utils_1.concat([
                utils_1.hexZeroPad(pubkey[0], 32),
                utils_1.hexZeroPad(pubkey[1], 32),
                utils_1.hexZeroPad(pubkey[2], 32),
                utils_1.hexZeroPad(pubkey[3], 32),
            ]));
            // return resolves to last 20 bytes of hashed public key
            return "0x" + payload.slice(payload.length - 40);
        };
        this.privateKey = () => utils_1.hexlify(privateKey);
        this.mclwasm = mcl.getMclInstance();
    }
    static async getBlsSigner(privateKey, domain) {
        mcl.setDomainHex(utils_1.hexlify(domain));
        await mcl.init();
        return new BlsSigner(privateKey);
    }
}
exports.BlsSigner = BlsSigner;
//# sourceMappingURL=index.js.map