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
     * 
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
     * @return PublicKey
     */
    static public function getPublic() {
        $public_key=self::getFile()->get('public_key');
        if($public_key)
            return PublicKeyLoader::loadPublicKey($public_key);
        return self::createKey('public');
    }

    /**
     * 获取私钥
     * 
     * @return PrivateKey
     */
    static public function getPrivate() {
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
    
}