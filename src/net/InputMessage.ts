import { Buffer } from "node:buffer";
import assert from "node:assert";

import { adler32 } from "~/utils/math";

const bufferMaxSize = 65536;
const maxHeaderSize = 8;
export default class InputMessage {
  _buffer: Buffer = Buffer.allocUnsafe(bufferMaxSize);
  _readPos: number = maxHeaderSize;
  _headerPos: number = maxHeaderSize;
  _messageSize: number = 0;

  constructor() {
    this.reset();
  }

  reset() {
    this._readPos = maxHeaderSize;
    this._headerPos = maxHeaderSize;
    this._messageSize = 0;
  }

  getReadSize() {
    return this._readPos - this._headerPos;
  }
  getReadPos() {
    return this._readPos;
  }
  getUnreadSize() {
    return this._messageSize - (this._readPos - this._headerPos);
  }
  getMessageSize() {
    return this._messageSize;
  }

  setBuffer(incomingBuffer: string) {
    this.reset();
    this.checkWrite(incomingBuffer.length);
    this._buffer = Buffer.from(incomingBuffer);
    this._readPos += this._buffer.length;
    this._messageSize = this._buffer.length;
  }

  canRead(bytes: number) {
    if (
      this._readPos - this._headerPos + bytes > this._messageSize ||
      this._readPos + bytes > bufferMaxSize
    ) {
      return false;
    }

    return true;
  }

  checkRead(bytes: number) {
    if (!this.canRead(bytes)) {
      throw new Error("InputMessage Not enough data to read");
    }
  }

  checkWrite(bytes: number) {
    if (bytes > bufferMaxSize) {
      throw new Error("InputMessage Buffer overflow");
    }
  }

  getU8() {
    this.checkRead(1);
    const value = this._buffer.readUInt8(this._readPos);
    this._readPos += 1;
    return value;
  }

  getU16() {
    this.checkRead(2);
    const value = this._buffer.readUInt16LE(this._readPos);
    this._readPos += 2;
    return value;
  }

  getU32() {
    this.checkRead(4);
    const value = this._buffer.readUInt32LE(this._readPos);
    this._readPos += 4;
    return value;
  }

  getU64() {
    this.checkRead(8);
    const value = this._buffer.readBigUInt64LE(this._readPos);
    this._readPos += 8;
    return value;
  }

  getString() {
    const length = this.getU16();
    this.checkRead(length);
    const value = this._buffer.toString(
      "ascii",
      this._readPos,
      this._readPos + length
    );
    this._readPos += length;
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

  fillBuffer(buffer: Buffer, size?: number) {
    const length = size ?? buffer.length;
    this.checkWrite(length);
    buffer.copy(this._buffer, this._readPos, 0);
    this._messageSize += length;
  }

  setHeaderSize(size: number) {
    assert(maxHeaderSize - size >= 0);
    this._headerPos = maxHeaderSize - size;
    this._readPos = this._headerPos;
  }

  readChecksum() {
    const expectedCheck = this.getU32();
    const checksumAbleBuffer = this._buffer.subarray(
      this._readPos,
      this.getUnreadSize()
    );

    const actualCheck = adler32(checksumAbleBuffer, checksumAbleBuffer.length);

    return expectedCheck === actualCheck;
  }
}
