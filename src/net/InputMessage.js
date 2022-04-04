import { Buffer } from "buffer";

import { adler32 } from "~/utils/math";

const bufferMaxSize = 65536;
const maxHeaderSize = 8;

export default class InputMessage {
  constructor() {
    this.reset();
  }

  reset() {
    this.readPos = maxHeaderSize;
    this.headerPos = maxHeaderSize;
    this.messageSize = 0;
  }

  getReadSize() {
    return this.readPos - this.headerPos;
  }
  getReadPos() {
    return this.readPos;
  }
  getUnreadSize() {
    return this.messageSize - (this.readPos - this.headerPos);
  }
  getMessageSize() {
    return this.messageSize;
  }

  setBuffer(incomingBuffer) {
    this.reset();
    this.checkWrite(incomingBuffer.length);
    this.buffer = Buffer.from(incomingBuffer);
    this.readPos += this.buffer.length;
    this.messageSize = this.buffer.length;
  }

  canRead(bytes) {
    if (
      this.readPos - this.headerPos + bytes > this.messageSize ||
      this.readPos + bytes > bufferMaxSize
    ) {
      return false;
    }

    return true;
  }

  checkRead(bytes) {
    if (!this.canRead(bytes)) {
      throw new Error("InputMessage Not enough data to read");
    }
  }

  checkWrite(bytes) {
    if (bytes > bufferMaxSize) {
      throw new Error("InputMessage Buffer overflow");
    }
  }

  getU8() {
    this.checkRead(1);
    const value = this.buffer.readUInt8(this.readPos);
    this.readPos += 1;
    return value;
  }

  getU16() {
    this.checkRead(2);
    const value = this.buffer.readUInt16LE(this.readPos);
    this.readPos += 2;
    return value;
  }

  getU32() {
    this.checkRead(4);
    const value = this.buffer.readUInt32LE(this.readPos);
    this.readPos += 4;
    return value;
  }

  getU64() {
    this.checkRead(8);
    const value = this.buffer.readBigUInt64LE(this.readPos);
    this.readPos += 8;
    return value;
  }

  getString() {
    const length = this.getU16();
    this.checkRead(length);
    const value = this.buffer.toString(
      "ascii",
      this.readPos,
      this.readPos + length
    );
    this.readPos += length;
    return value;
  }

  getDouble() {
    const precision = this.getU8();
    const value = this.getU32();
    return value / Math.pow(10, precision);
  }

  decryptRsa() {
    // TODO: implement
  }

  fillBuffer() {
    // TODO: implement
  }

  setHeaderSize(size) {
    asset(maxHeaderSize - size >= 0);
    this.headerPos = maxHeaderSize - size;
    this.readPos = this.headerPos;
  }

  readChecksum() {
    const expectedCheck = this.getU32();
    const actualCheck = adler32(
      this.buffer.slice(this.readPos, this.getUnreadSize())
    );
    return expectedCheck === actualCheck;
  }
}
