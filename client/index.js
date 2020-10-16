/**
 * num + content  aes对称加密    params1
 * num + 公钥      rsa非对称加密  params2
 * 客户端
 * 1.接收服务端传过来的公钥publicKey
 * 2.本地生成随机数num，通过与公钥进行rsa非对称加密生成params2，通过与content进行aes对称加密生成params1，发送给服务端
 * 3.接收服务端传过来的响应result，通过num进行对称解密
 * 服务端
 * 1.生成一对公钥和私钥，把公钥、对称加密的加密模式发送给客户端
 * 2.接收客户端传过来的params1、params2，把params2通过非对称rsa解密，得到num，然后通过对称解密aes，得到content
 * 3.把http响应数据result与num进行aes对称加密，发给客户端
 */

let aesKey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]; // 随机产生
let publicKey = ""; // 公钥会从服务端获取

/**
 * 登陆接口
 */
function submitFn() {
  const userName = document.querySelector("#userName").value;
  const password = document.querySelector("#password").value;
  const data = {
    userName,
    password,
  };

  const text = JSON.stringify(data);
  const sendData = aesEncrypt(text, aesKey); // 把要发送的数据转成字符串进行加密
  console.log("发送数据", text);

  const encrypt = new JSEncrypt();
  encrypt.setPublicKey(publicKey);
  const encrypted = encrypt.encrypt(aesKey.toString()); // 把aesKey进行非对称加密

  const url = "http://localhost:3000/login";
  const params = { id: 0, data: { param1: sendData, param2: encrypted } };

  axios({
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    url: url,
    data: JSON.stringify(params),
  })
    .then(function (result) {
      const reciveData = aesDecrypt(result.data.data, aesKey); // 用aesKey进行解密
      console.log("接收数据", reciveData);
    })
    .catch(function (error) {
      console.log("error", error);
    });
}

/**
 * aes加密方法
 * @param {string} text 待加密的字符串
 * @param {array} key 加密key
 */
function aesEncrypt(text, key) {
  const textBytes = aesjs.utils.utf8.toBytes(text); // 把字符串转换成二进制数据

  // 这边使用CTR-Counter加密模式，还有其他模式可以选择，具体可以参考aes加密库
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));

  const encryptedBytes = aesCtr.encrypt(textBytes); // 进行加密
  const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes); // 把二进制数据转成十六进制

  return encryptedHex;
}

/**
 * aes解密方法
 * @param {string} encryptedHex 加密的字符串
 * @param {array} key 加密key
 */
function aesDecrypt(encryptedHex, key) {
  const encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex); // 把十六进制数据转成二进制
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));

  const decryptedBytes = aesCtr.decrypt(encryptedBytes); // 进行解密
  const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes); // 把二进制数据转成utf-8字符串
  return decryptedText;
}

// 页面加载完之后，就去获取公钥
window.onload = () => {
  axios({
    method: "GET",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    url: "http://localhost:3000/getPub",
  })
    .then(function (result) {
      publicKey = result.data.data; // 获取公钥
    })
    .catch(function (error) {
      console.log(error);
    });
};
