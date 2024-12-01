<?php

include('rb-sqlite.php');
R::setup('sqlite:./data/keys.db');

$ip = "::1";
$machineID = "test-machine";
$poolID = "test-pool";

$acl = R::findOne('acl', ' ip = ? AND machine = ? AND pool = ? ', [$ip, $machineID, $poolID]);
if (is_null($acl)) {
    $acl = R::dispense('acl');
    $acl->ip = $ip;
    $acl->machine = $machineID;
    $acl->pool = $poolID;
    R::store($acl);
    die($acl);
}
else {
    die("already in db\n");
}

