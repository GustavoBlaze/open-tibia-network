import type { Buffer } from "node:buffer";
import OutputMessage from "~/net/OutputMessage";
import InputMessage from "~/net/InputMessage";

const ROUNDS = 32;
const DELTA = 0x9e3779b9;

export function decrypt(inputMessage: InputMessage, key: Buffer): Boolean {
  const encryptedSize = inputMessage.getUnreadSize();

  if (encryptedSize % 8 != 0) {
    console.log("[Error]: invalid encrypted network message");
    return false;
  }

  const xteaKey = Uint32Array.from([
    key.readUint32LE(0),
    key.readUint32LE(4),
    key.readUint32LE(8),
    key.readUint32LE(12),
  ]);

  const buffer = inputMessage.getReadBuffer();
  let readPos = 0;

  while (readPos < encryptedSize / 4) {
    let v0 = buffer.readUint32LE(readPos);
    let v1 = buffer.readUint32LE(readPos + 1);

    let sum = 0xc6ef3720;

    for (let i = 0; i < ROUNDS; i++) {
      v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + xteaKey[(sum >> 11) & 3]);
      sum -= DELTA;
      v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + xteaKey[sum & 3]);
    }

    buffer[readPos] = v0;
    buffer[readPos + 1] = v1;
    readPos += 2;
  }

  const decryptedSize = inputMessage.getU16() + 2;
  const sizeDelta = decryptedSize - encryptedSize;

  if (sizeDelta > 0 || -sizeDelta > encryptedSize) {
    console.log("[Error]: invalid decrypted network message 2");
    return false;
  }

  return true;
}

export function encrypt(outputMessage: OutputMessage, key: Buffer): void {
  outputMessage.writeMessageSize();
  let encryptedSize = outputMessage.getMessageSize();

  // add padding bytes if it needs
  if (encryptedSize % 8 != 0) {
    let padding = 8 - (encryptedSize % 8);
    outputMessage.addPaddingBytes(padding, 0);
    encryptedSize += padding;
  }

  const xteaKey = Uint32Array.from([
    key.readUint32LE(0),
    key.readUint32LE(4),
    key.readUint32LE(8),
    key.readUint32LE(12),
  ]);

  let readPos = 0;
  const buffer = outputMessage.getDataBuffer(-2);

  while (readPos) {
    let v0 = buffer.readUint32LE(readPos);
    let v1 = buffer.readUint32LE(readPos + 1);
    let sum = 0xc6ef3720;

    for (let i = 0; i < ROUNDS; i++) {
      v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + xteaKey[sum & 3]);
      sum -= DELTA;
      v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + xteaKey[(sum >> 11) & 3]);
    }

    buffer[readPos] = v0;
    buffer[readPos + 1] = v1;
    readPos += 2;
  }
}
