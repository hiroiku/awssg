<?php

class Aws
{
    private $groupId = '';
    private $describe = null;
    private $authorized = [];
    private $revoked = [];

    public function __construct($groupId)
    {
        $this->groupId = $groupId;
    }

    public function authorize($sourceIPs, $awsPortIPs)
    {
        $permissions = $this->authorizeDiff($sourceIPs, $awsPortIPs);
        $json = json_encode($permissions);

        if (count($permissions) > 0) {
            return `aws ec2 authorize-security-group-ingress --group-id {$this->groupId} --ip-permissions '{$json}'`;
        } else {
            return '';
        }
    }

    public function revoke($sourceIPs, $awsPortIPs)
    {
        $permissions = $this->revokeDiff($sourceIPs, $awsPortIPs);
        $json = json_encode($permissions);

        if (count($permissions) > 0) {
            return `aws ec2 revoke-security-group-ingress --group-id {$this->groupId} --ip-permissions '{$json}'`;
        } else {
            return '';
        }
    }

    public function authorizeDiff($sourceIPs, $awsPortIPs)
    {
        $permissions = [];

        foreach ($awsPortIPs as $port => $awsIPs) {
            $diff = array_diff($sourceIPs, $awsIPs);
            $this->authorized[$port] = $diff;

            if (count($diff) > 0) {
                $permissions[] = $this->permission($diff, $port);
            }
        }

        return $permissions;
    }

    public function revokeDiff($sourceIPs, $awsPortIPs)
    {
        $permissions = [];

        foreach ($awsPortIPs as $port => $awsIPs) {
            $diff = array_diff($awsIPs, $sourceIPs);
            $this->revoked[$port] = $diff;

            if (count($diff) > 0) {
                $permissions[] = $this->permission($diff, $port);
            }
        }

        return $permissions;
    }

    public function permission($ips, $port)
    {
        $permission = [
            'IpProtocol' => 'tcp',
            'FromPort' => $port,
            'ToPort' => $port,
            'IpRanges' => [],
        ];

        foreach ($ips as $ip) {
            $permission['IpRanges'][] = ['CidrIp' => $ip];
        }

        return $permission;
    }

    public function getPortIPs($ports)
    {
        $ips = [];
        foreach ($ports as $port) {
            $ips[$port] = $this->getIPs($port);
        }

        return $ips;
    }

    public function getIPs($port)
    {
        if (null === $this->describe) {
            $this->describe = json_decode(`aws ec2 describe-security-groups --group-id {$this->groupId}`, true);
        }
        $ips = [];

        if (!isset($this->describe['SecurityGroups'])) {
            return [];
        }

        foreach ($this->describe['SecurityGroups'] as $group) {
            if (!isset($group['IpPermissions'])) {
                return [];
            }

            foreach ($group['IpPermissions'] as $permission) {
                if (!isset($permission['FromPort']) || !isset($permission['IpRanges'])) {
                    return [];
                }

                if ($permission['FromPort'] == $port) {
                    foreach ($permission['IpRanges'] as $range) {
                        $ips[] = $range['CidrIp'];
                    }
                }
            }
        }

        return $ips;
    }

    public function getAuthorized()
    {
        return $this->authorized;
    }

    public function getRevoked()
    {
        return $this->revoked;
    }
}
