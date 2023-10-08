<?php

namespace app\index\service;

use AdminService\File;
use AdminService\App;

class Totp {

    /**
     * 服务端密钥
     * @var string
     */
    private string $server_code;

    /**
     * 客户端密钥
     * @var string
     */
    private string $client_code;

    /**
     * 每个验证码的有效时间
     * @var int
     */
    private int $period;

    /**
     * 验证码的位数
     * @var int
     */
    private int $digits;

    /**
     * 验证码容错率(周期,至少为1)
     * @var int
     */
    private int $max;

    /**
     * TOTP秘钥
     * @var string
     */
    private string $totp_key;

    /**
     * TOTP秘钥支持的字符集
     * @var string
     */
    private string $totp_charset='ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * File对象
     * @var File
     */
    private File $file;

    /**
     * 构造函数
     * 
     * @access public
     * @param string $server_code 服务端密钥
     * @param string $client_code 客户端密钥
     * @param File $file File对象
     * @param int $period 每个验证码的有效时间(时间片长度)
     * @param int $digits 验证码的位数
     * @param int $max 验证码容错率(周期,至少为1)
     */
    public function __construct(
        string $server_code,
        string $client_code,
        ?File $file=null,
        int $period=30,
        int $digits=6,
        int $max=1,
    ) {
        $this->server_code=base64_decode($server_code);
        $this->client_code=base64_decode($client_code);
        $this->file=$file??App::get('File');
        $this->period=$period;
        $this->digits=$digits;
        $this->max=$max;
        $this->totp_key=$this->getTotpKey();
    }

    /**
     * 获取TOTP秘钥
     * 
     * @access private
     * @return string
     */
    private function getTotpKey(): string {
            $totp_key=hash_hmac('sha256',$this->client_code,$this->server_code);
        return $totp_key;
    }

    /**
     * 获取某个时间戳的时间片
     * 
     * @access private
     * @param int $timestamp 时间戳
     * @return int
     */
    private function getTimeSlice(?int $timestamp=null): int {
        if($timestamp===null) $timestamp=time();
        return floor($timestamp/$this->period);
    }


    /**
     * 获取某个时间片的验证码
     * 
     * @access public
     * @param int $timeslice 时间片
     * @return string
     */
    public function getCode(?int $timeslice=null): string {
        $time_slice=$timeslice??$this->getTimeSlice();
        $len=($this->digits>0&&$this->digits<=21)?$this->digits:21;
        $key=$this->totp_key.'_'.$time_slice.'_'.$len;
        // 判断缓存中是否存在
        if($code=$this->file->get($key))
            return $code;
        $code=hash_hmac('sha256',$time_slice,$this->totp_key);
        $offset=hexdec(substr($code,-1));
        $code=substr($code,0,63);
        // 将code按3位一组分割
        $code=str_split($code,3);
        // 保留指定位数
        $code=array_slice($code,0,$len);
        // 先将每组的值转换为10进制,然后取模,最后转换为字符
        $code=array_map(function($value) use ($offset) {
            $value=hexdec($value);
            $value=($value+$offset)%strlen($this->totp_charset);
            return $this->totp_charset[$value];
        },$code);
        // 将数组合并为字符串
        $code=implode('',$code);
        // 保存到缓存中
        $this->file->set($key,$code,true);
        return $code;
    }

    /**
     * 获取某个时间片的过期时间
     * 
     * @access public
     * @param int $timeslice 时间片
     * @return int
     */
    public function getExpire(?int $timeslice=null): int {
        $time_slice=$timeslice??$this->getTimeSlice();
        return ($time_slice+1)*$this->period;
    }

    /**
     * 计算某个时间片的剩余时间
     * 
     * @access public
     * @param int $timeslice 时间片
     * @return int
     */
    public function getRemain(?int $timeslice=null): int {
        $time_slice=$timeslice??$this->getTimeSlice();
        return $this->getExpire($time_slice)-time();
    }

    /**
     * 验证验证码是否正确
     * 
     * @access public
     * @param string $code 验证码
     * @return bool
     */
    public function verify(string $code): bool {
        $code=strtoupper($code);
        // 最多向上或向下验证$max个时间片
        for($i=-$this->max;$i<=$this->max;$i++) {
            $timeslice=$this->getTimeSlice(time()+$i*$this->period);
            if($this->getCode($timeslice)==$code) return true;
        }
        return false;
    }

}