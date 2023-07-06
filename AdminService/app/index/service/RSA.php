<?php

namespace app\index\service;

use AdminService\File;
use AdminService\Config;
use phpseclib3\Crypt\RSA as RSACrypt;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Crypt\RSA\PrivateKey;

class RSA {

    /**
     * File 对象
     * @var File
     */
    static private File $File;

    /**
     * 获取 File 对象
     * @return File
     */
    static private function getFile() {
        if(!isset(self::$File))
            self::$File=new File(Config::get('rsa.key.name','rsa'));
        return self::$File;
    }

    /**
     * 获取公钥
     * 
     * @param string $public_key
     * @return PublicKey
     */
    static public function getPublic(string $public_key=null) {
        if($public_key!==null)
            return PublicKeyLoader::loadPublicKey($public_key);
        $public_key=self::getFile()->get('public_key');
        if($public_key)
            return PublicKeyLoader::loadPublicKey($public_key);
        return self::createKey('public');
    }

    /**
     * 获取私钥
     * 
     * @param string $private_key
     * @return PrivateKey
     */
    static public function getPrivate(string $private_key=null) {
        if($private_key!==null)
            return RSACrypt::loadPrivateKey($private_key);
        $private_key=self::getFile()->get('private_key');
        if($private_key)
            return RSACrypt::loadPrivateKey($private_key);
        return self::createKey('private');
    }

    /**
     * 创建秘钥
     * 
     * @param string $type
     * @return PrivateKey|PublicKey
     */
    static public function createKey(string $type) {
        $private=RSACrypt::createKey(Config::get('rsa.key.bit',2048));
        $public=$private->getPublicKey();
        // 保存秘钥
        self::getFile()->set('private_key',$private->toString('PKCS8'));
        self::getFile()->set('public_key',$public->toString('PKCS8'));
        self::getFile()->save();
        // 返回秘钥
        if($type=='private')
            return $private;
        return $public;
    }

    /**
     * 使用公钥加密
     * 
     * @param string $data
     * @param PublicKey $public
     * @return string
     */
    static public function encrypt(string $data,PublicKey $public=null) {
        if($public===null)
            $public=self::getPublic();
        $length=($public->getLength()-2*$public->getHash()->getLength()-16)>>3;
        $max_length=strlen($data);
        $enstr='';
        for($i=0;$i<$max_length;$i+=$length)
            $enstr.=$public->encrypt(substr($data,$i,$length));
        return $enstr;
    }

    /**
     * 使用私钥解密
     * 
     * @param string $data
     * @param PrivateKey $private
     * @return string
     */
    static public function decrypt(string $data,PrivateKey $private=null) {
        if($private===null)
            $private=self::getPrivate();
        $length=$private->getLength()>>3;
        $destr='';
        for($i=0;$i<strlen($data);$i+=$length) {
            $destr.=$private->decrypt(substr($data,$i,$length));
        }
        return $destr;
    }
    
}