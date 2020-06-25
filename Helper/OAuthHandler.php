<?php

namespace Miniorange\Helper;

class OAuthHandler {

    function getAccessToken($tokenendpoint, $grant_type, $clientid, $clientsecret, $code, $redirect_url, $send_headers, $send_body){
        $response = $this->getToken ($tokenendpoint, $grant_type, $clientid, $clientsecret, $code, $redirect_url, $send_headers, $send_body);
        $content = json_decode($response,true);

        if(isset($content["access_token"])) {
            return $content["access_token"];
            exit;
        } else {
            echo 'Invalid response received from OAuth Provider. Contact your administrator for more details.<br><br><b>Response : </b><br>'.$response;
            exit;
        }
    }

    function getToken($tokenendpoint, $grant_type, $clientid, $clientsecret, $code, $redirect_url, $send_headers, $send_body){

//        $ch = curl_init($tokenendpoint);
//        curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
//        curl_setopt( $ch, CURLOPT_ENCODING, "" );
//        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
//        curl_setopt( $ch, CURLOPT_AUTOREFERER, true );
//        curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
//        curl_setopt( $ch, CURLOPT_MAXREDIRS, 10 );
//        curl_setopt( $ch, CURLOPT_POST, true);

        $ch = $this->prepareCurlOptions($tokenendpoint);

        if($send_headers && !$send_body) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Authorization: Basic ' . base64_encode( $clientid . ":" . $clientsecret ),
                'Accept: application/json'
            ));
            curl_setopt( $ch, CURLOPT_POSTFIELDS, 'redirect_uri='.urlencode($redirect_url).'&grant_type='.$grant_type.'&code='.$code);

        }else if(!$send_headers && $send_body){

            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Accept: application/json'
            ));
            curl_setopt( $ch, CURLOPT_POSTFIELDS, 'redirect_uri='.urlencode($redirect_url).'&grant_type='.$grant_type.'&client_id='.$clientid.'&client_secret='.$clientsecret.'&code='.$code);
        }else {

            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Authorization: Basic ' . base64_encode( $clientid . ":" . $clientsecret ),
                'Accept: application/json'
            ));
            curl_setopt( $ch, CURLOPT_POSTFIELDS, 'redirect_uri='.urlencode($redirect_url).'&grant_type='.$grant_type.'&client_id='.$clientid.'&client_secret='.$clientsecret.'&code='.$code);
        }

        $response = curl_exec($ch);

        if(curl_error($ch)){
            echo "<b>Response : </b><br>";print_r($response);echo "<br><br>";
            exit( curl_error($ch) );
        }

        if(!is_array(json_decode($response, true))){
            echo "<b>Response : </b><br>";print_r($response);echo "<br><br>";
            exit("Invalid response received.");
        }

        $response = json_decode($response,true);

        if (isset($response["error"])) {
            if (is_array($response["error"])) {
                $response["error"] = $response["error"]["message"];
            }
            exit($response["error"]);
        }
        else if(isset($response["error_description"])){
            exit($response["error_description"]);
        }
//        else if(isset($response["access_token"])) {
//            $access_token = $response["access_token"];
//        } else {
//            exit('Invalid response received from OAuth Provider. Contact your administrator for more details.\n\m'.$response);
//        }
        return $response;

//        $body = array(
//            'grant_type'    => $grant_type,
//            'code'          => $code,
//            'client_id'     => $clientid,
//            'client_secret' => $clientsecret,
//            'redirect_uri'  => $redirect_url,
//        );
//        $field_string = json_encode ( $body );
//
//        $headers = array(
//            'Accept'  => 'application/json',
//            'charset'       => 'UTF - 8',
//            'Authorization' => 'Basic ' . base64_encode( $clientid . ':' . $clientsecret ),
//            'Content-Type' => 'application/x-www-form-urlencoded',
//        );
//
//        if($send_headers && !$send_body){
//            unset( $body['client_id'] );
//            unset( $body['client_secret'] );
//        }else if(!$send_headers && $send_body){
//            unset( $headers['Authorization'] );
//        }
//
//        $ch = $this->prepareCurlOptions($tokenendpoint, $field_string, $headers);
//
//        $response = curl_exec ($ch);
//
//        error_log("get_token response : ".$response);
//
//        if (curl_errno ( $ch )) {
//            echo 'Error in sending curl Request';
//            exit ();
//        }
//
//        curl_close ( $ch );
//        return $response;

    }

    function getIdToken($tokenendpoint, $grant_type, $clientid, $clientsecret, $code, $redirect_url, $send_headers, $send_body){
        $content = $this->getToken ($tokenendpoint, $grant_type, $clientid, $clientsecret, $code, $redirect_url, $send_headers, $send_body);

//        $content = json_decode($response,true);
        if(isset($content["id_token"]) || isset($content["access_token"])) {
            return $content;
            exit;
        } else {
            echo 'Invalid response received from OpenId Provider. Contact your administrator for more details.<br><br><b>Response : </b><br>'.$response;
            exit;
        }
    }

    function getResourceOwnerFromIdToken($id_token){
        $id_array = explode(".", $id_token);
        if(isset($id_array[1])) {
            $id_body = base64_decode($id_array[1]);
            if(is_array(json_decode($id_body, true))){
                return json_decode($id_body,true);
            }
        }
        echo 'Invalid response received.<br><b>Id_token : </b>'.$id_token;
        exit;
    }

    function getResourceOwner($resourceownerdetailsurl, $access_token){
        $headers = array();
        $headers['Authorization'] = 'Bearer '.$access_token;

        $response   = wp_remote_post( $resourceownerdetailsurl, array(
            'method'      => 'GET',
            'timeout'     => 45,
            'redirection' => 5,
            'httpversion' => '1.0',
            'blocking'    => true,
            'headers'     => $headers,
            'cookies'     => array(),
            'sslverify'   => false
        ) );

        $response =  $response['body'] ;
        $response = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($match) {
            return mb_convert_encoding(pack('H*', $match[1]), 'UTF-8', 'UCS-2BE');
        }, $response);
        $response = addcslashes($response,'\\');

        if(!is_array(json_decode($response, true))){
            echo "<b>Response : </b><br>";print_r($response);echo "<br><br>";
            exit("Invalid response received.");
        }

        $content = json_decode($response,true);
        if(isset($content["error_description"])){
            exit($content["error_description"]);
        } else if(isset($content["error"])){
            exit($content["error"]);
        }

        return $content;
    }

    function getResponse($url){
        $response = wp_remote_get($url, array(
            'method' => 'GET',
            'timeout' => 45,
            'redirection' => 5,
            'httpversion' => 1.0,
            'blocking' => true,
            'headers' => array(),
            'cookies' => array(),
            'sslverify' => false,
        ));

        $content = json_decode($response,true);
        if(isset($content["error_description"])){
            exit($content["error_description"]);
        } else if(isset($content["error"])){
            exit($content["error"]);
        }

        return $content;
    }

    function prepareCurlOptions($url){
        $ch = curl_init($url);
        curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt( $ch, CURLOPT_ENCODING, "" );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
        curl_setopt( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt( $ch, CURLOPT_POST, true);
//        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
        curl_setopt($ch, CURLOPT_PROXY, '127.0.0.1:8888');

        return $ch;
    }

}

