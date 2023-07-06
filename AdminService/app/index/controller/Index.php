<?php

namespace app\index\controller;

use \Exception;
use base\Controller;
use app\index\service\RSA;

class Index extends Controller {

    public function index() {
        try {
            $public=RSA::getPrivate();
            return $public->toString('PKCS8');
        } catch (Exception $error) {
            return $error->getMessage();
        }
    }

    public function test() {
        try {
            // $data="OCSXtapUn2zgQgYfQ5+yfkdKGkrBtD9R8JhxoJVWqRsQC+8TNnwEqOHJVL92u9Ni9H+ekfHL6HM/irQXM6vtmrum5eTuuL3mLUz1TxrZOWAFsp2hwISHxAv1PTqaTEDbB/GmhU0bzDi5YIKxUoK3KIuAh3iVTg7sTdDQCYk3VQIiRdCEDTdPSRfAORRVKMwNgqXYWOHVOsiS7qksatwphI6E9Y5wokHqzaZYDfE+iDxXZilWiMNFleXpWq5xzdwxm1FkuSYatOfKpqiswiFhaCJI42O4Jbn4RVaLmwtlRrTxvz+92bEFWKHO9LdklqMS2vjmDuZqkQV8HbZCO5VJzg==";
            // print_r(RSA::getPublic()->withPadding(\phpseclib3\Crypt\RSA::ENCRYPTION_PKCS1)->getPadding());
            // echo RSA::decrypt(RSA::encrypt($data));
            // echo base64_encode(RSA::encrypt('1'));
            // echo "源内容:".$data."<br>\n";
            // $data=base64_decode($data);
            // echo "base64解码:".$data."<br>\n";
            // $data=RSA::decrypt($data);
            // echo "RSA解密:".$data."<br>\n";
        } catch (Exception $error) {
            echo "错误:".$error->getMessage()."<br>\n";
        }
    }

}

?>