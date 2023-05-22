import Vue from 'vue'
import CryptoJS from "crypto-js";
import JsEncrypt from 'jsencrypt'
import jsRsasign from 'jsrsasign'

//对数据进行加密
export const $ENCRYPT = (a) => {
  console.log('来自全局')
  let postData={AESKey:'',Data:'',Sign:''}
  postData.Data=JSON.stringify(a)
  //AESKey生成16位随机数
  postData.AESKey = $randomString();
  //ASES加密Data
  postData.Data = $getAESEncryption(postData.Data,postData.AESKey) 
  //服务器公钥加密AESKey
  postData.AESKey = $rsaEncrypt(postData.AESKey)
  //签名加密
  postData.Sign = $getSignCode(postData.AESKey)
  return postData
}

//对数据进行解密
export const $DECRYPT = (a) => {
  let data=JSON.parse(a)
  if($attestationCode(data.AESKey,data.Sign)){
    data.AESKey = $rsaDecrypt(data.AESKey)
    data.Data = $getAESDecryption(data.Data,data.AESKey) 
  }
  console.log('解密',data.Data)
  return data
}

// 生成16位随机字符串
export const $randomString = (len) => {
  len = len || 16;
  /*默认去掉了容易混淆的字符oOLl,9gq,Vv,Uu,I1*/
  var $chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";
  var maxPos = $chars.length;
  var randomKey = "";
  for (var i = 0; i < len; i++) {
    randomKey += $chars.charAt(Math.floor(Math.random() * maxPos));
  }
  return randomKey;
}

//AES加密
//@param word 加密内容
//@param keyStr 十六位的十六进制数作为 加解密的密钥，一般是动态生成（这里由randomString方法生成）
export const $AesEncrypt = (word, keyStr) => {
  var key = CryptoJS.enc.Utf8.parse(keyStr);
  var srcs = CryptoJS.enc.Utf8.parse(word);
  var iv = CryptoJS.enc.Utf8.parse('&rklP!6w~jKnCD+!');
  var encrypted = CryptoJS.AES.encrypt(srcs, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
  });
  return encrypted.toString();
}

export const $AesDecrypt = (word, keyStr) => {
  var key = CryptoJS.enc.Utf8.parse(keyStr);
  var iv = CryptoJS.enc.Utf8.parse('&rklP!6w~jKnCD+!');
  var decrypt = CryptoJS.AES.decrypt(word, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
  });
  return CryptoJS.enc.Utf8.stringify(decrypt).toString();
}

export const $getAESEncryption = (content, randomKey) => {
  var encryption = $AesEncrypt(content, randomKey);
  return encryption;
}

export const $getAESDecryption = (content, aeskey) => {
  var decryption = $AesDecrypt(content, aeskey);
  return decryption;
}

//服务器公钥
let PublicKey=`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8SOXoSG5xMe7yr7dnKS4sf/0L
zywjsDWOraEBIm8rLrcjOk3yWCnKarwU3PFLxllwm1138BqjRgWt6klvJBhMlPH5
C9vYyL8t4O8v8up5aJtVMZT6hYYeJUMIXky/k5LBCFyXdMrpOaWQs8lCW6kxRya8
oxdFUoNWEePgOwPRKwIDAQAB
-----END PUBLIC KEY-----`

//本地私钥
let LocalKey=`-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMwpkBuYQAaZE+x6
UY/O0iUAatqu+bkEvhGHjGzuFKa1Avs4WV8r4je2ak+w9SBPyUQtS2+dsyJt5F5w
CBxU84y+TIoGeFpL0YzFyXRU80b8A3vkC+9tOEYCRXvU72Vw0KoGFN+JsKPj11c0
apxF8QiU9eTCQQ8DKLcj4uBd16WLAgMBAAECgYEAnBEBmjaOavzFoDX490eQmLxy
8mxjdS3M5bWKgRKWMsGYX9Y5a2kuaoxFRFnvaB3Vqwo86jvQ3fbHZfGaIZ5G9egr
pHrqWgh/weg90JjkXEoN5/elNbKrnTpFt0pe4wPaWJc4hq/VyRKtHwCFMYOoGdhI
XZ2rEVjVpXX/lURluSECQQDrnRn0bkle5OWB7wbctYP2e8R7CP/Uzw0vJUNcpBMX
88U8mkw71YjG5ygWIpr4ZTxJKgqrd1F6FBa2baxXm4rJAkEA3dPOrIKIxU18SkM4
CTy+dhzBD2WSe1lUl8tLfSM4vgiaLFnu7J7lOyMh2scCKtISta8vd2oThtuWZ1IM
3ytDswJBAIHn/rV8UUvW3IvFZH0wP3AZUX2cuqF0/4ns+7UKadSc/TSqxjl/RIiW
Ts3ViqhF+PVGDtf3U58BkHxI/+rVwbECQD+FmsZdrurJEJF3hEFo6qWKAGL3VCYM
Y6QALELOZj5M2lFfA4Mw0TXJDrXGjUFT3NW4L+CDOMpCcWRu4464pe8CQH9jC+XM
+1KOdt7J+Mk2KOr9IOs4pjykvqfUUI8h6lVvR2c7fDWwEGU+4NYwnLeoTIImz/IW
SiLmRwA5oqoVZCQ=
-----END PRIVATE KEY-----`

//RSA加密
export const $rsaEncrypt = (strIng) => {
  // 实例化一个JSEncrypt对象
  let jse = new JsEncrypt();
  // 设置公钥（公钥秘钥需自己生成）
  jse.setPublicKey(PublicKey);
  // 加密
  let encrypted = jse.encrypt(strIng);
  return encrypted;
}

//RSA解密
export const $rsaDecrypt = (strIng) => {
  let jse = new JsEncrypt();
  // 设置秘钥
  jse.setPrivateKey(LocalKey);
  // 解密加密过的字符串
  let decrypted = jse.decrypt(strIng);
  // 打印结果
  return decrypted;
}

//Sign加密
export const $getSignCode = (strIng) => {
  // 创建RSAKey对象
  var rsa = new jsRsasign.RSAKey();
  //因为后端提供的是pck#8的秘钥对，所以这里使用 KEYUTIL.getKey来解析秘钥
  var signPrivateKey = LocalKey
  // 将密钥转码,其实就是将头部尾部默认字符串去掉
  signPrivateKey = jsRsasign.KEYUTIL.getKey(signPrivateKey);
  // 创建Signature对象，设置签名编码算法
  // alg:对应的是规则 需要和后端统一
  var sig = new jsRsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA", "prov": "cryptojs/jsrsa", "prvkeypem": signPrivateKey });
  // 初始化
  sig.init(signPrivateKey)
  // 传入待加密字符串
  sig.updateString(strIng);
  // 生成密文
  var sign = jsRsasign.hextob64(sig.sign());
  return sign;
}

//验证签名
//@param {String} strIng 签名前的明文
//@param {String} data 签名后的数据
//@return {Boolean} true | false
export const $attestationCode = (strIng, data) => {
  // 创建RSAKey对象
  var rsa = new jsRsasign.RSAKey();
  //因为后端提供的是pck#8的公钥对，所以这里使用 KEYUTIL.getKey来解析公钥
  var signPublicKey = PublicKey
  // 将公钥转码
  signPublicKey = jsRsasign.KEYUTIL.getKey(signPublicKey);
  // 创建Signature对象，设置签名编码算法
  var sig = new jsRsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA", "prov": "cryptojs/jsrsa", "prvkeypem": signPublicKey });
  // 初始化
  sig.init(signPublicKey)
  // 传入待加密字符串
  sig.updateString(strIng);
  // !接受的参数是16进制字符串!
  let sign = sig.verify(jsRsasign.b64tohex(data));
  return sign;
}
