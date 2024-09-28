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
    
    public static function encrypt($msg, $key, $iv = null) {
        $iv_size = openssl_cipher_iv_length('AES-256-CBC');
        if (!$iv) {
            $iv = openssl_random_pseudo_bytes($iv_size);
        }
        $encryptedMessage = openssl_encrypt($msg, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encryptedMessage);
    }

    public static function decrypt($encrypted, $key) {
        $data = base64_decode($encrypted);
        $iv_size = openssl_cipher_iv_length('AES-256-CBC');
        $iv = substr($data, 0, $iv_size); // Extract IV
        $encryptedMessage = substr($data, $iv_size); // Extract encrypted message
        
        // Decrypt the message
        return openssl_decrypt($encryptedMessage, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    
    public static function generate_key($length = 32) {
        return bin2hex(random_bytes($length/2));
    }
}

$x = EAS::decrypt("tyVS55kHHaAUWwIByizLwJqI1n4CRUNgrqYyOkMSaIGqdP/1qwy/3f+tWnrtNqgaiFMTQrbG8TShLW8E1Xk04fCRq/Hr+VX/On+5DAotnoytKxaHhqkB4zFQRBu2vzeM", "bd0515d236a7b5825dbf0de50362811a");
print($x);