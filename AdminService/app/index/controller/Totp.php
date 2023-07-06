<?php

namespace app\index\controller;

use \Exception;
use base\Controller;
use AdminService\Log;
use AdminService\File;
use app\index\service\RSA;

use function AdminService\common\json;

class Totp extends Controller {

    public function init(Log $Log) {
        try {
            $s=$this->param('s','');
            if(!$s) throw new Exception('参数错误');
            $Log->write($s);
            $data=json_decode(RSA::decrypt(base64_decode($s)),true);
            $Log->write($data);
            if(!$data['public_key'] || !$data['username'] || !$data['client_code'])
                return throw new Exception('参数不完整');
            $public=RSA::getPublic($data['public_key']);
            // 这里只是简单判断下用户,实际上应该是从数据库中获取用户信息并且应该验证签名和检查登录状态
            $File=new File('totp');
            $user_info=$File->get($data['username']);
            $server_code=$user_info['server_code']??$this->randstring(32);
            $client_code=$data['client_code'];
            $File->set($data['username'],[
                'server_code'=>$server_code,
                'client_code'=>$client_code,
            ],true);
            // 将数据加密后返回,实际上应该需要签名
            $data=array(
                'server_code'=>$server_code,
                'client_code'=>$client_code,
            );
            $Log->write("{data}",$data);
            $data=RSA::encrypt(json_encode($data),$public);
            return json(1,'success',base64_encode($data));
        } catch (Exception $error) {
            $Log->write($error->getMessage());
            return json(0,$error->getMessage());
        }
    }

    /**
     * 生成随机字符串
     * 
     * @param int $length 长度
     * @return string
     */
    private function randstring($length=32) {
        $str='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $strlen=strlen($str)-1;
        $randstr='';
        for($i=0;$i<$length;$i++){
            $num=mt_rand(0,$strlen);
            $randstr .= $str[$num];
        }
        return base64_encode($randstr);
    }

}

?>