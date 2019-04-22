<?php

class Http
{
    public static function from()
    {
        return new static();
    }

    public function url($url)
    {
        $ips = file_get_contents($url);
        $ips = preg_replace('/\r\n|\r|\n/', PHP_EOL, $ips);
        $ips = explode(PHP_EOL, $ips);
        $ips = array_values(array_filter($ips));

        return $ips;
    }
}
