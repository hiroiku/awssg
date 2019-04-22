<?php

require_once __DIR__.'/Aws.php';
require_once __DIR__.'/Http.php';

$short_options = [];
$long_options = [
    'group-id:',
    'port:',
    'from:',
    'http-port::',
    'https-port::',
];
$options = getopt(implode('', $short_options), $long_options);
$ports = explode(',', $options['port']);
$sourceIPs = Http::from()->url($options['from']);
$aws = new Aws($options['group-id']);
$awsPortIPs = $aws->getPortIPs($ports);

$aws->authorize($sourceIPs, $awsPortIPs);
foreach ($aws->getAuthorized() as $port => $ips) {
    foreach ($ips as $ip) {
        echo "+ {$ip}:{$port}".PHP_EOL;
    }
}

$aws->revoke($sourceIPs, $awsPortIPs);
foreach ($aws->getRevoked() as $port => $ips) {
    foreach ($ips as $ip) {
        echo "- {$ip}:{$port}".PHP_EOL;
    }
}
