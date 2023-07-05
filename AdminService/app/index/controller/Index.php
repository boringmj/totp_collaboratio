<?php

namespace app\index\controller;

use \Exception;
use base\Controller;
use app\index\service\RSA;

class Index extends Controller {

    public function index() {
        try {
            $public=RSA::getPublic();
            echo $public->toString('PKCS8');
        } catch (Exception $error) {
            echo $error->getMessage();
        }
    }

}

?>