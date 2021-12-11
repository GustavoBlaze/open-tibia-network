// Testing RSA encryption
const { RSA } = require("./utils/crypt");

const rsa = new RSA({
  n: "109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413",
});

const buffer = Buffer.alloc(128);
const message = "Hello, world!";

buffer.write(message, 0, message.length, "ascii");

const encrypted = rsa.encrypt(buffer);

console.log({ encrypted });
