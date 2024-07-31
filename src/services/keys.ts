import * as ed from "@noble/ed25519";
import { bech32 } from "bech32";
import * as blake from "blakejs";


const KEYHASH_LENGTH = 28;
const ADDR_LENGTH = KEYHASH_LENGTH * 2 + 1;

// Stores ed25519 KeyPair and hash of publicKey
export class Ed25519Key {
    private: Uint8Array;
    public: Uint8Array;
    pkh: Uint8Array;

    private constructor(priv: Uint8Array, pub: Uint8Array, pkh: Uint8Array) {
        this.private = priv;
        this.public = pub;
        this.pkh = pkh;
    }
    public static async generate() {
        const privKey = ed.utils.randomPrivateKey(); // Secure random private key
        return await Ed25519Key.fromPrivateKey(privKey);
    }

    public static async fromPrivateKey(privKey: Uint8Array) {
        const pubKey = await ed.getPublicKeyAsync(privKey);
        const pkh = blake.blake2b(pubKey, undefined, KEYHASH_LENGTH);
        const key = new Ed25519Key(privKey, pubKey, pkh);
        console.log("loaded", "Ed25519Key", key.json());
        return key;
    }
    public static async fromPrivateKeyHex(privKey:string) {
        return await Ed25519Key.fromPrivateKey(
            Uint8Array.from(Buffer.from(privKey, "hex"))
        );
    }

    public bech32Pkh(prefix: string = "stake"): string {
        return bech32.encode(prefix, bech32.toWords(this.pkh));
    }
    public bech32PublicKey(prefix: string = "vk_"): string {
        return bech32.encode(prefix, bech32.toWords(this.public));
    }
    public bech32PrivateKey(prefix: string = "sk_"): string {
        return bech32.encode(prefix, bech32.toWords(this.private));
    }
    public async signRaw(message: Uint8Array) {
        return await ed.signAsync(message, this.private);
    }
    public async verify(message:Buffer, signature:Buffer) {
        return await ed.verifyAsync(signature, message, this.public);
    }

    public json() {
        return {
            private: Buffer.from(this.private).toString("hex"),
            public: Buffer.from(this.public).toString("hex"),
            pkh: Buffer.from(this.pkh).toString("hex"),
        };
    }
    public static fromJson(json: any): Ed25519Key {
        if (!json || typeof json !== "object") {
            throw new Error(
                "Invalid JSON format for Ed25519Key: Input must be a non-null object."
            );
        }

        if (!json.private || !json.public || !json.pkh) {
            throw new Error(
                "Invalid JSON format for Ed25519Key: Missing required fields (private, public, or pkh)."
            );
        }

        return new Ed25519Key(
            Uint8Array.from(Buffer.from(json.private, "hex")),
            Uint8Array.from(Buffer.from(json.public, "hex")),
            Uint8Array.from(Buffer.from(json.pkh, "hex"))
        );
    }
}

// Shelley Wallet has 2 ed25519 key pair
// - one for payment purpose
// - one for staking/governance purpose
export class ShelleyWallet {
    paymentKey: Ed25519Key;
    stakeKey: Ed25519Key;

    public constructor(payment:Ed25519Key, stake:Ed25519Key) {
        this.paymentKey = payment;
        this.stakeKey = stake;
    }

    public static async generate() {
        const wallet = new ShelleyWallet(
            await Ed25519Key.generate(),
            await Ed25519Key.generate()
        );
        console.log("generated", "Ed25519Key", wallet);
        return wallet;
    }

    addressBech32(networkId: number): string {
        const prefix = networkId == 0 ? "addr_test" : "addr";
        return bech32.encode(
            prefix,
            bech32.toWords(Buffer.from(this.addressRawBytes(networkId))),
            200
        );
    }

    addressRawBytes(networkId:number) {
        const concatenatedArray1 = new Uint8Array(ADDR_LENGTH);
        concatenatedArray1[0] = networkId;
        concatenatedArray1.set(this.paymentKey.pkh, 1);
        concatenatedArray1.set(this.stakeKey.pkh, KEYHASH_LENGTH + 1);
        return concatenatedArray1;
    }
    rewardAddressRawBytes(network: number) {
        const rewardAccountPrefix = 0xe0;
        const header = network | rewardAccountPrefix;
        const result = new Uint8Array(KEYHASH_LENGTH + 1);
        result[0] = header;
        result.set(this.stakeKey.pkh, 1);
        return result;
    }

    rewardAddressBech32(networkId: number): string {
        const prefix = networkId == 0 ? "stake_test" : "stake";
        return bech32.encode(
            prefix,
            bech32.toWords(Buffer.from(this.rewardAddressRawBytes(networkId))),
            200
        );
    }
    public toJSON() {
        return {
            payment: this.paymentKey.json(),
            stake: this.stakeKey.json(),
        };
    }

    public static fromJson(obj: {
        payment: object;
        stake: object;
    }): ShelleyWallet {
        if (!obj || typeof obj !== "object") {
            throw new Error("ShelleyWallet.fromJson: The input must be an object.");
        }

        const paymentKey = obj.payment;
        const stakeKey = obj.stake;

        if (!paymentKey || typeof paymentKey !== "object") {
            throw new Error(
                "ShelleyWallet.fromJson : Invalid payment key: It must be an object."
            );
        }

        if (!stakeKey || typeof stakeKey !== "object") {
            throw new Error(
                "ShelleyWallet.fromJson : Invalid stake key: It must be an object."
            );
        }
        return new ShelleyWallet(
            Ed25519Key.fromJson(paymentKey),
            Ed25519Key.fromJson(stakeKey)
        );
    }

}

export interface Address {
    paymentKeyHash: Uint8Array;
    stakeKeyHash?: Uint8Array
    toBech32(): string;
    toRawBytes(): Uint8Array;
    toRawBytesHex(): string;
}

export class ShelleyWalletAddress implements Address {
    paymentKeyHash: Uint8Array;
    stakeKeyHash: Uint8Array;
    network: number;

    private constructor(
        network: number | "mainnet" | "testnet",
        pkh: Uint8Array,
        skh: Uint8Array
    ) {
        this.network =
            network == "mainnet" ? 1 : network == "testnet" ? 0 : network;
        this.paymentKeyHash = pkh;
        this.stakeKeyHash = skh;
    }
    public static fromRawBytes(bytea: Uint8Array | string | Buffer) {
        let bytebuffer: Buffer;
        if (bytea.length == ADDR_LENGTH * 2 && typeof bytea == "string") {
            bytebuffer = Buffer.from(bytea, "hex");
        } else {
            if (bytea.length !== ADDR_LENGTH) {
                throw Error(
                    "ShelleyAddress.fromRawBytes: Invalid byte array length. expected: " +
                    ADDR_LENGTH +
                    " got: " +
                    bytea.length
                );
            }
            bytebuffer = Buffer.from(bytea);
        }

        let paymentKeyHash = bytebuffer.subarray(1, 29);
       
        let stakeKeyHash = bytebuffer.length >29 ? bytebuffer.subarray(29, ADDR_LENGTH):undefined;

        return new ShelleyWalletAddress(
            bytebuffer.at(0)!,
            paymentKeyHash,
            stakeKeyHash
        );
    }
    toBech32(): string {
        const prefix = this.network == 0 ? "addr_test" : "addr";
        return bech32.encode(
            prefix,
            bech32.toWords(Buffer.from(this.toRawBytes())),
            200
        );
    }
    toRawBytes(): Uint8Array {
        const addrLen = this.stakeKeyHash? (KEYHASH_LENGTH+1):ADDR_LENGTH
        const rawBytes = new Uint8Array(addrLen);
        rawBytes[0] = this.network;
        rawBytes.set(this.paymentKeyHash, 1);
        if (this.stakeKeyHash)
            rawBytes.set(this.stakeKeyHash, KEYHASH_LENGTH + 1);
        return rawBytes;
    }
    toRawBytesHex(): string {
        return Buffer.from(this.toRawBytes()).toString("hex");
    }
    toJSON():string{
        return this.toBech32();
    }
}