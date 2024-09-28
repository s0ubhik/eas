<?php

class EAS {
    public static function pkcs7_pad($data, $blocksize) {
        $pad = $blocksize - (strlen($data) % $blocksize);
        return $data . str_repeat(chr($pad), $pad);
    }
    
    public static function pkcs7_unpad($data) {
        $pad = ord($data[strlen($data) - 1]);
        return substr($data, 0, -$pad);
    }
    
    public static function encrypt($data, $key) {
        $key = str_pad($key, 32);
        $iv = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
        $paddedData = static::pkcs7_pad($data, 16);
        
        $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $paddedData, MCRYPT_MODE_CBC, $iv);
        
        return base64_encode($iv . $ciphertext);
    }
    
    public static function decrypt($ciphertext, $key) {
        $key = str_pad($key, 32); 
        $data = base64_decode($ciphertext);
        
        $iv = substr($data, 0, 16); 
        $encryptedData = substr($data, 16);
        
        $decryptedPaddedData = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $encryptedData, MCRYPT_MODE_CBC, $iv);
        
        return static::pkcs7_unpad($decryptedPaddedData);
    }
    
    public static function generate_key($length = 32) {
        return bin2hex(random_bytes($length/2));
    }
}

