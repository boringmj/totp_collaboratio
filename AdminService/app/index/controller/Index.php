<?php

namespace app\index\controller;

use \Exception;
use base\Controller;
use AdminService\File;
use AdminService\Config;
use app\index\service\RSA;
use app\index\service\Totp;
use phpseclib3\Crypt\RSA as RSACrypt;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Crypt\RSA\PrivateKey;

use function AdminService\common\json;

class Index extends Controller {

    public function index() {
        return $this->view();
    }

    public function public_key() {
        try {
            $public=RSA::getPublic();
            return json(1,'success',array('public'=>$public->toString('PKCS8')));
        } catch (Exception $error) {
            return json(0,$error->getMessage());
        }
    }

    public function key() {
        try {
            $bits=Config::get('rsa.key.bit',2048);
            $private=RSACrypt::createKey($bits);
            $public=$private->getPublicKey();
            return json(null,null,array(
                'bits'=>$bits,
                'private'=>$private->toString('PKCS8'),
                'public'=>$public->toString('PKCS8'),
                'type'=>'PKCS8'
            ));
        } catch (Exception $error) {
            return json(0,$error->getMessage());
        }
    }

}

?>