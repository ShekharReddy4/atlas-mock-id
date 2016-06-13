<?php

require("config.php");

$user = $_POST['user'];
$mdp = $_POST['password'];

if ($user == null || $mdp == null){
	header('Location: auth.html');
	exit();
}

if ($users[$user]['password'] == $mdp){

	$entity = json_encode($users[$user]);

	$salted = $api_key . $site_key;
	$digest = hash('sha1', $salted, true);
	$key    = substr($digest, 0, 16);
	$iv = 'OpenSSL for Node';
	$pad = 16 - (strlen($entity) % 16);
	$entity = $entity . str_repeat(chr($pad), $pad);

	$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128,'','cbc','');
	mcrypt_generic_init($cipher, $key, $iv);
	$multipass = mcrypt_generic($cipher,$entity);
	mcrypt_generic_deinit($cipher);

	preg_replace('/\n/g', '', $multipass);
	preg_replace('/\//g', '_', $multipass);
	preg_replace('/\//g', '_', $multipass);

	$multipass = base64_encode($multipass);

	$signature = hash_hmac("sha1", $multipass, $api_key, true);
	$signature = base64_encode($signature);

	$hash = base64_encode(hash_hmac("sha1", $multipass, $api_key, true));

	$multipass = urlencode($multipass);
	$signature = urlencode($signature);

	header("Location: ". $redirect_url . "auth/multipass/callback?multipass=" . $multipass . "&signature=" . $signature);
	exit();

} else {
	echo "Bad password";
	header('Location: auth.html');
	exit();
}