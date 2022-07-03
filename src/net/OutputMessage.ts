import { Buffer } from "node:buffer";
import { adler32 } from "~/utils/math";
import type { RSA } from "~/utils/crypt";
import assert from "node:assert";

const bufferMaxSize = 65536;
const maxStringSize = 65536;
const maxHeaderSize = 8;

export default class OutputMessage {
  _buffer: Buffer;
  _rsa?: RSA;
  _writePos: number = maxHeaderSize;
  _headerPos: number = maxHeaderSize;
  _messageSize: number = 0;

  constructor(rsa: RSA) {
    this._buffer = Buffer.allocUnsafe(bufferMaxSize);
    this._rsa = rsa;
    this.reset();
  }

  reset() {
    this._writePos = maxHeaderSize;
    this._headerPos = maxHeaderSize;
    this._messageSize = 0;
  }

  canWrite(bytes: number) {
    return this._writePos + bytes <= bufferMaxSize;
  }

  checkWrite(bytes: number) {
    if (!this.canWrite(bytes)) {
      throw new Error("OutputMessage buffer overflow");
    }
  }

  addU8(value: number) {
    this.checkWrite(1);
    this._buffer.writeUInt8(value, this._writePos);
    this._writePos += 1;
    this._messageSize += 1;
  }

  addU16(value: number) {
    this.checkWrite(2);
    this._buffer.writeUInt16LE(value, this._writePos);
    this._writePos += 2;
    this._messageSize += 2;
  }

  addU32(value: number) {
    this.checkWrite(4);
    this._buffer.writeUInt32LE(value, this._writePos);
    this._writePos += 4;
    this._messageSize += 4;
  }

  addU64(value: bigint) {
    this.checkWrite(8);
    this._buffer.writeBigUInt64LE(value, this._writePos);
    this._writePos += 8;
    this._messageSize += 8;
  }

  addString(value: string) {
    if (value.length > maxStringSize) {
      throw new Error("OutputMessage string too long");
    }

    this.checkWrite(value.length + 2);
    this.addU16(value.length);
    this._buffer.write(value, this._writePos, value.length, "ascii");

    this._writePos += value.length;
    this._messageSize += value.length;
  }

  addPaddingBytes(quantity: number, value: number) {
    if (quantity <= 0) return;

    this.checkWrite(quantity);
    this._buffer.fill(value, this._writePos, this._writePos + quantity);
    this._writePos += quantity;
    this._messageSize += quantity;
  }

  encryptRSA() {
    if (!this._rsa) {
      throw new Error("OutputMessage RSA instance is not set");
    }

    const rsaSize = this._rsa.getSize();

    if (this._messageSize < rsaSize) {
      throw new Error("OutputMessage Insufficient message size to encrypt");
    }

    const partToEncrypt = this._buffer.subarray(
      this._writePos - rsaSize,
      rsaSize
    );

    this._rsa.encrypt(partToEncrypt);
  }

  writeChecksum() {
    const checksumAbleBuffer = this._buffer.subarray(
      this._headerPos,
      this._messageSize
    );

    const checksum = adler32(checksumAbleBuffer, checksumAbleBuffer.length);

    assert(this._headerPos - 4 >= 0);

    this._headerPos -= 4;
    this._buffer.writeUInt32LE(checksum, this._headerPos);
    this._messageSize += 4;
  }

  writeMessageSize() {
    assert(this._headerPos - 2 >= 0);
    this._headerPos -= 2;
    this._buffer.writeUInt16LE(this._messageSize, this._headerPos);
    this._messageSize += 2;
  }
}
