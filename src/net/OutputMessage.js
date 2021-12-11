const { Buffer } = require("buffer");
const { adler32 } = require("~/utils/math");

const bufferMaxSize = 65536;
const maxStringSize = 65536;
const maxHeaderSize = 8;

export default class OutputMessage {
  constructor() {
    this.buffer = Buffer.allocUnsafe(bufferMaxSize);

    this.reset();
  }

  reset() {
    this.writePos = maxHeaderSize;
    this.headerPos = maxHeaderSize;
    this.messageSize = 0;
  }

  canWrite(bytes) {
    return this.writePos + bytes <= bufferMaxSize;
  }

  checkWrite(bytes) {
    if (!this.canWrite(bytes)) {
      throw new Error("OutputMessage buffer overflow");
    }
  }

  addU8(value) {
    this.checkWrite(1);
    this.buffer.writeUInt8(value, this.writePos);
    this.writePos += 1;
    this.messageSize += 1;
  }

  addU16(value) {
    this.checkWrite(2);
    this.buffer.writeUInt16LE(value, this.writePos);
    this.writePos += 2;
    this.messageSize += 2;
  }

  addU32(value) {
    this.checkWrite(4);
    this.buffer.writeUInt32LE(value, this.writePos);
    this.writePos += 4;
    this.messageSize += 4;
  }

  addU64(value) {
    this.checkWrite(8);
    this.buffer.writeUInt64LE(value, this.writePos);
    this.writePos += 8;
    this.messageSize += 8;
  }

  addString(value) {
    if (value.length > maxStringSize) {
      throw new Error("OutputMessage string too long");
    }

    this.checkWrite(value.length + 2);
    this.addU16(value.length);
    this.buffer.write(value, this.writePos, value.length, "ascii");

    this.writePos += value.length;
    this.messageSize += value.length;
  }

  addPaddingBytes(quantity, value) {
    if (quantity <= 0) return;

    this.checkWrite(quantity);
    this.buffer.fill(value, this.writePos, this.writePos + quantity);
    this.writePos += quantity;
    this.messageSize += quantity;
  }

  writeChecksum() {
    const checksum = adler32(this.buffer, this.headerPos, this.messageSize);
    assert(this.headerPos - 4 >= 0);
    this.headerPos -= 4;
    this.buffer.writeUInt32LE(checksum, this.headerPos);
    this.messageSize += 4;
  }

  writeMessageSize() {
    assert(this.headerPos - 2 >= 0);
    this.headerPos -= 2;
    this.buffer.writeUInt16LE(this.messageSize, this.headerPos);
    this.messageSize += 2;
  }
}
