<?php

namespace app\index\controller;

use \Exception;
use base\Controller;
use AdminService\Log;
use AdminService\File;
use app\index\service\RSA;
use app\index\service\Totp as TotpService;

use function AdminService\common\json;

class Totp extends Controller {

    public function init(Log $Log) {
        try {
            $s=$this->param('s','');
            if(!$s) throw new Exception('参数错误');
            $Log->write("接收到请求: {s}",array(
                's'=>$s,
            ));
            $data=RSA::decrypt(base64_decode($s));
            $Log->write("解密后的数据: {data}",array(
                'data'=>$data,
            ));
            $data=json_decode($data,true);
            $Log->write("json解析后的数据: {data}",array(
                'data'=>$data,
            ));
            if(empty($data['public_key']) || empty($data['username']) || empty($data['client_code']))
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
            $Log->write("回传的数据: {data}",array(
                'data'=>$data,
            ));
            $data=RSA::encrypt(json_encode($data),$public);
            return json(1,'success',base64_encode($data));
        } catch (Exception $error) {
            $Log->write($error->getMessage());
            return json(0,$error->getMessage());
        }
    }

    public function check(Log $Log) {
        try {
            $s=$this->param('s','');
            if(!$s) throw new Exception('参数错误');
            $Log->write("接收到请求: {s}",array(
                's'=>$s,
            ));
            $data=RSA::decrypt(base64_decode($s));
            $Log->write("解密后的数据: {data}",array(
                'data'=>$data,
            ));
            $data=json_decode($data,true);
            $Log->write("json解析后的数据: {data}",array(
                'data'=>$data,
            ));
            if(empty($data['username']) || empty($data['code']))
                return throw new Exception('参数不完整');
            $File=new File('totp');
            $user_info=$File->get($data['username']);
            $server_code=$user_info['server_code']??'';
            $client_code=$user_info['client_code']??'';
            if(!$server_code || !$client_code)
                return throw new Exception('用户不存在');
            $Totp=new TotpService($server_code,$client_code);
            if(!$Totp->verify($data['code']))
                return throw new Exception('验证码错误');
            return json(1,'success');
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