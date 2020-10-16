const http = require("http");
const aesjs = require("aes-js");
const NodeRSA = require("node-rsa");
const rsaKey = new NodeRSA({ b: 1024 }); // key的size为1024位
let aesKey = null; // 用于保存客户端的aesKey
let privateKey = ""; // 用于保存服务端的公钥

rsaKey.setOptions({ encryptionScheme: "pkcs1" }); // 设置加密模式
http
  .createServer((request, response) => {
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
    response.setHeader("Content-Type", "application/json");
    switch (request.method) {
      case "GET":
        if (request.url === "/getPub") {
          const publicKey = rsaKey.exportKey("public");
          privateKey = rsaKey.exportKey("private");
          response.writeHead(200);
          response.end(JSON.stringify({ result: true, data: publicKey })); // 把公钥发送给客户端
          return;
        }
        break;
      case "POST":
        if (request.url === "/login") {
          let str = "";
          request.on("data", function (chunk) {
            str += chunk;
          });
          request.on("end", function () {
            const params = JSON.parse(str);
            const reciveData = decrypt(params.data);
            console.log("reciveData", reciveData);
            // 一系列处理之后

            response.writeHead(200);
            response.end(
              JSON.stringify({
                result: true,
                data: aesEncrypt(
                  JSON.stringify({ userId: 123, address: "杭州" }), // 这个数据会被加密
                  aesKey
                ),
              })
            );
          });
          return;
        }
        break;
      default:
        break;
    }
    response.writeHead(404);
    response.end();
  })
  .listen(3000);

function decrypt({ param1, param2 }) {
  const decrypted = rsaKey.decrypt(param2, "utf8"); // 解密得到aesKey
  aesKey = decrypted.split(",").map((item) => {
    return +item;
  });

  return aesDecrypt(param1, aesKey);
}

/**
 * aes解密方法
 * @param {string} encryptedHex 加密的字符串
 * @param {array} key 加密key
 */
function aesDecrypt(encryptedHex, key) {
  const encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex); // 把十六进制转成二进制数据
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5)); // 这边使用CTR-Counter加密模式，还有其他模式可以选择，具体可以参考aes加密库

  const decryptedBytes = aesCtr.decrypt(encryptedBytes); // 进行解密
  const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes); // 把二进制数据转成字符串

  return decryptedText;
}

/**
 * aes加密方法
 * @param {string} text 待加密的字符串
 * @param {array} key 加密key
 */
function aesEncrypt(text, key) {
  const textBytes = aesjs.utils.utf8.toBytes(text); // 把字符串转成二进制数据
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));

  const encryptedBytes = aesCtr.encrypt(textBytes); // 加密
  const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes); // 把二进制数据转成十六进制

  return encryptedHex;
}
