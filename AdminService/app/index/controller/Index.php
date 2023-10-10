<?php

namespace app\index\controller;

use \Exception;
use base\Controller;
use AdminService\File;
use app\index\service\RSA;
use app\index\service\Totp;

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

    public function test() {
        try {
            // $data="leF+o4zA1Ci4+WNtE4LzH3dgZOqFM7V5KZXDZVBd6meUG33j7G9P9CXr6qA6SlxwwtaTUqcZY5c672/Fk9EeCzJcb3BNpMg9XpnTH0KZlKa4jft+t0VvqMIb6oGwa3v/1WGyLUoqsNx9C+K5R0gxdFqJiQWfWLdDD7kcPUeP2p1qcxSmMBbtEpTf3dkFxyQUgeqpjHsofdCT8LO1w5i0bkm1W1y9Qzv+Mk/Fz2phCBM2baky7FmeJwneLwgXObQy7D9mgV9JEr+lP3WBeNzYXTttqU0Z8fabrrxRyCF1WemSZYSmlBpME9RvoNI2GHrJjiFy9YC1EZFbiDvk0XQxSIjRWrPSfV2ZFnhZCPIDcBpXv+2pJmgWxHVNbWfSW7BMnkcioQCtKoiAsWzpQrE597MHksY9/jvX7+zNnxCvxz5M3NrFMMwRmEXQfiWnnFCWBNH9loagplf5MxpUXSVHfWQQKhmlqRwpYk62sDMPcuQXn2Ih8W9GQqpWUCv+Dqdhcd4jTgyIblzPVnFOT++Jl2rBgm9rgB03Uupq7GBaqBaxq0ASS0YXixFcrqQE6tBlQZpoWTb8HfBkzVA1y8HGwcM8r/CveJTQxw+Gb2JdC7IPs/B8/PeDqjsNr3W1dZ5ybsHGB4pJiRR1xIG1mqA0omPW07CqL4/bqebjJ6ybXQgX5gJSBTkQwjW6y7bqkAFGmyWFkgKx8AhP/fDRr1N+ez+bOpR/TWKfvlVUk4xKbN6r5aLVfattM0Z06z19ScgQL28KRfv5dmpSx7fmTaIk8iXSp9ZjStEIE2KI5EtXgPo4chm4JpJkkylHixKZ6RgBsmh+sCHcIV9xXiBc4kOOsYz7AZP+s2gfzM4GDheZL0HpDWTkxuNM+tJjWoWBsKZWkWnCxAecmHzrN8xe2/RX4ZDF3Xj/GB7D7cpeIPkKcJGkGYASqqTHINbqDw9aBs9zIQt8ETB7aiabqxgtN6tt7sLm0kicrMZJl4/jSofbFRX2PbRE4TPJinP2tn8ZcMLU";
            // // print_r(RSA::getPublic()->withPadding(\phpseclib3\Crypt\RSA::ENCRYPTION_PKCS1)->getPadding());
            // // echo RSA::decrypt(RSA::encrypt($data));
            // // echo base64_encode(RSA::encrypt('1'));
            // echo "源内容:".$data."<br>\n";
            // $data=base64_decode($data);
            // echo "base64解码:".$data."<br>\n";
            // $data=RSA::decrypt($data);
            // echo "RSA解密:".$data."<br>\n";
            $File=new File('totp');
            $info=$File->get('nan1a5');
            $Totp=new Totp($info['server_code'],$info['client_code']);
            echo "当前验证码:".$Totp->getCode();
            echo "<br>\n";
            echo "剩余时间:".$Totp->getRemain();
        } catch (Exception $error) {
            echo "错误:".$error->getMessage()."<br>\n";
        }
    }

}

?>