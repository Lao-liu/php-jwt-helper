<?php

require_once './jwtHelper.php';

$secret = 'lunchleague';

$jwtA = JWTHelper::new(["alg" => "HS256"], ["sub" => "A"], $secret);
$parsedJwtA = JWTHelper::parse($jwtA);
$jwtAValidity = JWTHelper::validate($jwtA, $secret);
$jwtASegments = JWTHelper::split($jwtA);

$jwtB = JWTHelper::new(["alg" => "HS256"], ["sub" => "B"], $secret);
$parsedJwtB = JWTHelper::parse($jwtB);
$jwtBSegments = JWTHelper::split($jwtB);
$jwtBValidity = JWTHelper::validate($jwtA, $secret);

$jwtAMod = "$jwtBSegments[0].$jwtBSegments[1].$jwtASegments[2]";
$modJwtValidity = (JWTHelper::validate($jwtAMod, $secret)) ? 1 : 'invalid';

echo "<span class=\"title\">JWT A: </span>";
echo "<br><br>";
echo $jwtA;

echo "<br><br>";
echo "<span class=\"title\">Decoded JWT A: </span>";
echo "<br><br>";
print_r($parsedJwtA);

echo "<br><br>";
echo "<span class=\"title\">JWT A Validity: </span>";
echo "<br><br>";
echo $jwtAValidity;

echo "<hr>";
echo "<span class=\"title\">JWT B: </span>";
echo "<br><br>";
echo $jwtB;

echo "<br><br>";
echo "<span class=\"title\">Decoded JWT B: </span>";
echo "<br><br>";
print_r($parsedJwtB);

echo "<br><br>";
echo "<span class=\"title\">JWT B Validity: </span>";
echo "<br><br>";
echo $jwtBValidity;

echo "<hr>";
echo "<br>";
echo "<span class=\"title\">Modded JWT A Validity: </span>";
echo "<br><br>";
echo $modJwtValidity;

echo "<style>.title { font-weight: bold; text-decoration: underline; }</style>";

