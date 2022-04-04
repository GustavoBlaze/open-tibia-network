var BigInteger = require("jsbn").BigInteger;

class RSA {
  pkcs1pad2(s, n) {
    if (n < s.length + 11) {
      throw new Error("Message too long for RSA");
      return null;
    }
    var ba = [];
    var i = s.length - 1;
    while (i >= 0 && n > 0) {
      var c = s.charCodeAt(i--);
      ba[--n] = c;
    }
    ba[--n] = 0;
    while (n > 2) {
      ba[--n] = Math.floor(Math.random() * 256);
    }
    ba[--n] = 2;
    ba[--n] = 0;
    return new BigInteger(ba);
  }

  parseBigInt(str, r) {
    return new BigInteger(str, r);
  }

  setPublic(N, E) {
    if (N != null && E != null && N.length > 0 && E.length > 0) {
      this.n = parseBigInt(N, 10);
      this.e = parseInt(E, 10);
    } else throw new Error("Invalid RSA public key");
  }

  encrypt(text) {
    var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
    if (m == null) return null;
    var c = this.doPublic(m);
    if (c == null) return null;
    var h = c.toString(16);
    if ((h.length & 1) == 0) return h;
    else return "0" + h;
  }
}

const rsa = new RSA();
rsa.setPublic(
  `109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413`,
  `65537`
);

export default rsa;
