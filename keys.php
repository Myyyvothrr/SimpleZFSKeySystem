<?php
/**
 * Simple Key System
 *   taking care of ZFS keys used in encryption
 *
 * @see https://github.com/chani/SimpleZFSKeySystem
 * @see https://blog.jeanbruenn.info/2023/11/11/encryption-of-zfs-volumes-using-a-remote-external-key-system-written-in-php/
 * @author Jean Bruenn <himself@jeanbruenn.info> 
 */
include('rb-sqlite.php');
R::setup('sqlite:./data/keys.db');

function fa($string){
  $string = preg_replace('([^a-zA-Z0-9-])', '', $string);
  return $string;
}

$protocol = $_SERVER['SERVER_PROTOCOL'];
$ip = $_SERVER['REMOTE_ADDR'];

$request = filter_var(substr($_SERVER['REQUEST_URI'], 1), FILTER_SANITIZE_URL);
$req = preg_split('_/_', $request);
$machineID = fa($req[0]);
$poolID = fa($req[1]);
$name = fa($req[2]);

$acl = R::findOne('acl', ' ip = ? AND machine = ? AND pool = ? ', [$ip, $machineID, $poolID]);
if(is_null($acl)){
    header($protocol.' 403 Forbidden');
    die();
} else {
    $machine = R::findOne('machine', ' guid = ? ', [$machineID]);
    if(is_null($machine)){
        $machine = R::dispense('machine');
        $machine->guid = $machineID;
        $machine->address = $ip;
        R::store($machine);
    }

    $pool = R::findOne('pool', ' guid = ? AND machine = ? ', [$poolID, $machine->guid]);
    if(is_null($pool)){
        $pool = R::dispense('pool');
        $pool->guid = $poolID;
        $pool->machine = $machine->guid;
        R::store($pool);
    }

    $key = R::findOne('key', ' name = ? AND machine = ? AND pool = ? ', [ $name, $machine->guid, $pool->guid ]);
    if(is_null($key)){
        $keyvalue = bin2hex(openssl_random_pseudo_bytes(16));
        $key = R::dispense('key');
        $key->keyvalue = $keyvalue;
        $key->name = $name;
        $key->active = true;
        $key->machine = $machine->guid;
        $key->pool = $pool->guid;
        R::store($key);
    }

    if($key->active == true){
        die($key->keyvalue);
    } else {
        header($protocol.' 403 Forbidden');
        die();
    }
}
