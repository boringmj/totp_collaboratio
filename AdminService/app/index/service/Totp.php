<?php

namespace app\index\service;

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
     * 构造函数
     * 
     * @access public
     * @param string $server_code 服务端密钥
     * @param string $client_code 客户端密钥
     * @param int $period 每个验证码的有效时间
     * @param int $digits 验证码的位数
     * @param int $max 验证码容错率(周期,至少为1)
     */
    public function __construct(
        string $server_code,
        string $client_code,
        int $period=30,
        int $digits=6,
        int $max=1,
    ) {
        $this->server_code=base64_decode($server_code);
        $this->client_code=base64_decode($client_code);
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
        if(!$this->totp_key)
            $this->totp_key=hash_hmac('sha256',$this->client_code,$this->server_code);
        return $this->totp_key;
    }



}