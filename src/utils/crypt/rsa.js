import { BigInteger } from "jsbn";
import { KJUR } from "jsrsasign";
import crypto from "crypto";

import { hex2b64, wordwrap } from "~/utils/string";

export default class RSA {
  constructor({ n, e = "65537" }) {
    this.n = new BigInteger(n);
    this.size = this.n.bitLength() / 8;
    this.e = Number(e);
  }

  getSize() {
    return this.size;
  }

  getPublicBaseKey() {
    const firstSequence = new KJUR.asn1.DERSequence({
      array: [
        new KJUR.asn1.DERObjectIdentifier({ oid: "1.2.840.113549.1.1.1" }), // RSA Encryption pkcs #1 oid
        new KJUR.asn1.DERNull(),
      ],
    });

    const secondSequence = new KJUR.asn1.DERSequence({
      array: [
        new KJUR.asn1.DERInteger({ bigint: this.n }),
        new KJUR.asn1.DERInteger({ int: this.e }),
      ],
    });

    const bitString = new KJUR.asn1.DERBitString({
      hex: "00" + secondSequence.getEncodedHex(),
    });

    const seq = new KJUR.asn1.DERSequence({
      array: [firstSequence, bitString],
    });

    return seq.getEncodedHex();
  }

  getPublicBaseKeyB64() {
    return hex2b64(this.getPublicBaseKey());
  }

  getPublicKeyDER() {
    let key = "-----BEGIN PUBLIC KEY-----\n";
    key += wordwrap(this.getPublicBaseKeyB64()) + "\n";
    key += "-----END PUBLIC KEY-----";
    return key;
  }

  encrypt(buffer) {
    const publicKey = this.getPublicKeyDER();

    return crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_NO_PADDING,
      },
      buffer
    );
  }
}
