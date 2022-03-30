import type Fio from "../../src/fio"
import {getFio} from "../test_utils"
import {hex_to_buf} from "../../src/utils/serialize"
import { HexString } from "types/internal";

describe("runTestsDevice", async () => {
    let fio: Fio = {} as Fio

    beforeEach(async () => {
        fio = await getFio()
    })

    afterEach(async () => {
        await (fio as any).t.close()
    })

    it("Should run device tests", async () => {
        console.log("???????????????????????????? runTests result");
        const res = await fio.runTests()
        console.log("???????????????????????????? runTests result");
        console.log(res)
    })

    it("Should play with fio DH encryption", async () => {
        //compute shared secret
        const PrivateKey = require('@fioprotocol/fiojs/dist/ecc/key_private')
        const privateKeyHex1 = "4d597899db76e87933e7c6841c2d661810f070bad20487ef20eb84e182695a3a" as HexString
        const privateKey1 = PrivateKey(hex_to_buf(privateKeyHex1))

        const PublicKey = require('@fioprotocol/fiojs/dist/ecc/key_public')
        const publicKeyHex2 = "0484e52dfea57b8f1787488a356374cd8e8515b8ad8db3dd4f9088d8e42ed2fb6d571e8894cccbdbf15e1bd84f8b4362f52d1b5b712b9775c0a51cdd5ee9a9e8ca" as HexString;
        const publicKey2 = PublicKey(hex_to_buf(publicKeyHex2));

        const sharedSecret = privateKey1.getSharedSecret(publicKey2);
        console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!! Shared secret JS");
        console.log(sharedSecret.toString("hex"));

        //compute IV
        const IV = Buffer.from('f300888ca4f512cebdc0020ff0f7224c', 'hex');        
        console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!! IV JS");
        console.log(IV.toString("hex"));

        //compute msg - this is sligtly more fancy in the example - fio serialization involved, but we already know how to deal with this
        const message = Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "hex");
        console.log(message.length);

        //compute K
        const hash = require('@fioprotocol/fiojs/dist/ecc/hash');
        const createHash = require('create-hash')
        const K = createHash('sha512').update(sharedSecret).digest();
        const Ke = K.slice(0, 32); // Encryption
        const Km = K.slice(32); // MAC
        console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!! K JS");
        console.log(K.toString("hex"));

        //encrypt the message
        const crypto = require('browserify-aes');
        const cipher = crypto.createCipheriv('aes-256-cbc', Ke, IV);
        const C = Buffer.concat([cipher.update(message), cipher.final()]);
        console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!! C JS");
        console.log(C.toString("hex"));



        // Include in the HMAC input everything that impacts the decryption
        //const M = createHmac('sha256', Km).update(Buffer.concat([IV, C])).digest(); // AuthTag
        //return Buffer.concat([IV, C, M]);


//        return new SharedCipher({sharedSecret, textEncoder, textDecoder});
    })
})
