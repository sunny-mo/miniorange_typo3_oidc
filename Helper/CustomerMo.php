<?php

namespace Miniorange\Helper;

use Miniorange\Helper\Constants;

class CustomerMo {

    public $email;
    public $phone;

    private $defaultCustomerKey = Constants::DEFAULT_CUSTOMER_KEY;
    private $defaultApiKey = Constants::HOSTNAME;

    function create_customer($email,$password) {

        $url = Constants::HOSTNAME.'/moas/rest/customer/add';
        // $current_user = wp_get_current_user();
        $this->email = $email;
        $password = $password;
        $fields = array (
            'companyName' => $_SERVER['SERVER_NAME'],
            'areaOfInterest' => Constants::AREA_OF_INTEREST,
            'email' => $this->email,
            'password' => $password
        );
        $field_string = json_encode ( $fields );
        $ch = $this->prepareCurlOptions($url,$field_string);
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
            'Content-Type: application/json',
            'charset: UTF - 8',
            'Authorization: Basic'
        ) );

        $response = curl_exec( $ch );
        error_log("create_customer response : ".$response);
        if (curl_errno ( $ch )) {
            echo 'Request Error:' . curl_error ( $ch );
            exit ();
        }

        curl_close ( $ch );
        return $response;
    }

//    function create_customer(){
//        $url = \MiniOrange\Helper\Constants::HOSTNAME . '/moas/rest/customer/add';
//        $this->email 		= get_option('mo_oauth_admin_email');
//        $this->phone 		= get_option('mo_oauth_admin_phone');
//        $password 			= get_option('password');
//        $firstName    		= get_option('mo_oauth_admin_fname');
//        $lastName     		= get_option('mo_oauth_admin_lname');
//        $company      		= get_option('mo_oauth_admin_company');
//
//        $fields = array(
//            'companyName' => $company,
//            'areaOfInterest' => 'WP OAuth Client',
//            'firstname'	=> $firstName,
//            'lastname'	=> $lastName,
//            'email'		=> $this->email,
//            'phone'		=> $this->phone,
//            'password'	=> $password
//        );
//        $field_string = json_encode($fields);
//        $headers = array( 'Content-Type' => 'application/json', 'charset' => 'UTF - 8', 'Authorization' => 'Basic' );
//        $args = array(
//            'method' =>'POST',
//            'body' => $field_string,
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//
//        return wp_remote_retrieve_body($response);
//    }

    public function submit_contact($email, $phone, $query)
    {
        $this->objectManager = GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');
        error_log(" TYPO3 SUPPORT QUERY : ");

        sendMail:
        $url = Constants::HOSTNAME.'/moas/api/notify/send';
        $subject = "miniOrange Typo3 OpenID Connect Query";

        $customerKey = MoUtilities::fetch_cust(Constants::CUSTOMER_KEY);
        $apiKey      = MoUtilities::fetch_cust(Constants::CUSTOMER_API_KEY);;

        if($customerKey==""){
            $customerKey= $this->defaultCustomerKey ;
            $apiKey = "$this->defaultApiKey";
        }

        $currentTimeInMillis = round(microtime(true) * 1000);
        $stringToHash = $customerKey . number_format($currentTimeInMillis, 0, '', '') . $apiKey;
        $hashValue = hash("sha512", $stringToHash);
        $customerKeyHeader = "Customer-Key: " . $customerKey;
        $timestampHeader = "Timestamp: " . number_format($currentTimeInMillis, 0, '', '');
        $authorizationHeader = "Authorization: " . $hashValue;

        $content = '<div >Hello, <br><br><b>Company :</b><a href="' . $_SERVER['SERVER_NAME'] . '" target="_blank" >' . $_SERVER['SERVER_NAME'] . '</a><br><br><b>Phone Number :</b>' . $phone . '<br><br><b>Email :<a href="mailto:' . $email . '" target="_blank">' . $email . '</a></b><br><br><b>Query: ' . $query . '</b></div>';

        $support_email_id = 'info@xecurify.com';

        $fields = array(
            'customerKey' => $customerKey,
            'sendEmail' => true,
            'email' => array(
                'customerKey' => $customerKey,
                'fromEmail'   => $email,
                'fromName'    => 'miniOrange',
                'toEmail'     => $support_email_id,
                'toName'      => $support_email_id,
                'bccEmail'    => "saml2support@xecurify.com",
                'subject'     => $subject,
                'content'     => $content
            ),
        );
        $field_string = json_encode($fields);

        error_log("TYPO3 support content : ".print_r($content,true));

        $ch = $this->prepareCurlOptions($url,$field_string);
        curl_setopt($ch, CURLOPT_HTTPHEADER,
                            array("Content-Type: application/json",
                                $customerKeyHeader,
                                $timestampHeader,
                                $authorizationHeader)
                    );

        $response = curl_exec($ch);
        error_log("submit_contact rsponse : ".$response);

        if (curl_errno($ch)) {
            $message = GeneralUtility::makeInstance(FlashMessage::class,'CURL ERROR','Error',FlashMessage::ERROR,true);
            $out = GeneralUtility::makeInstance(ListRenderer ::class)->render([$message]);
            echo $out;
            return;
        }

        curl_close($ch);
        return $response;

    }

    function check_customer($email,$password) {
        $url = Constants::HOSTNAME."/moas/rest/customer/check-if-exists";
        $fields = array (
            'email' => $email
        );
        $field_string = json_encode ( $fields );

        $ch = $this->prepareCurlOptions($url,$field_string);
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
            'Content-Type: application/json',
            'charset: UTF - 8',
            'Authorization: Basic'
        ) );

        $response = curl_exec ( $ch );
        error_log("check_customer response : ".$response);

        if (curl_errno ( $ch )) {
            echo 'Error in sending curl Request';
            exit ();
        }
        curl_close ( $ch );

        return $response;
    }

    function get_customer_key($email,$password) {
        $url = Constants::HOSTNAME."/moas/rest/customer/key";
        $fields = array (
            'email' => $email,
            'password' => $password
        );
        $field_string = json_encode ( $fields );
    
        $ch = $this->prepareCurlOptions($url,$field_string);
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, array (
            'Content-Type: application/json',
            'charset: UTF - 8',
            'Authorization: Basic'
        ) );

        $response = curl_exec ( $ch );
        error_log("get_customer_key response : ".$response);

        if (curl_errno ( $ch )) {
            echo 'Error in sending curl Request';
            exit ();
        }
        curl_close ( $ch );

        return $response;
    }

    function mo_get_current_domain() {
        $http_host = $_SERVER['HTTP_HOST'];
        if(substr($http_host, -1) == '/') {
            $http_host = substr($http_host, 0, -1);
        }
        $request_uri = $_SERVER['REQUEST_URI'];
        if(substr($request_uri, 0, 1) == '/') {
            $request_uri = substr($request_uri, 1);
        }

        $is_https = (isset($_SERVER['HTTPS']) && strcasecmp($_SERVER['HTTPS'], 'on') == 0);
        $relay_state = 'http' . ($is_https ? 's' : '') . '://' . $http_host;
        return $relay_state;
    }

//    ----------OAuth Specific--------------------------
//    function add_oauth_application( $name, $app_name ) {
//        $url = get_option('host_name') . '/moas/rest/application/addoauth';
//        $customerKey = get_option('mo_oauth_admin_customer_key');
//        $scope = get_option('mo_oauth_' . $name . '_scope');
//        $client_id = get_option('mo_oauth_' . $name . '_client_id');
//        $client_secret = get_option('mo_oauth_' . $name . '_client_secret');
//        if($scope != false) {
//            $fields = array(
//                'applicationName'	=> $app_name,
//                'scope'				=> $scope,
//                'customerId' 		=> $customerKey,
//                'clientId' 			=> $client_id,
//                'clientSecret' 		=> $client_secret
//            );
//        } else {
//            $fields = array(
//                'applicationName'	=> $app_name,
//                'customerId' 		=> $customerKey,
//                'clientId' 			=> $client_id,
//                'clientSecret' 		=> $client_secret
//            );
//        }
//        $field_string = json_encode( $fields );
//
//        $headers = array( 'Content-Type' => 'application/json', 'charset' => 'UTF - 8', 'Authorization' => 'Basic' );
//        $args = array(
//            'method' =>'POST',
//            'body' => $field_string,
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//
//        return wp_remote_retrieve_body($response);
//    }
//
//    private static function createAuthHeader($customerKey, $apiKey)
//    {
//        $currentTimestampInMillis = self::getTimestamp();
//        if(MoUtility::mo_is_empty_or_null($currentTimestampInMillis))
//        {
//            $currentTimestampInMillis = round(microtime(true) * 1000);
//            $currentTimestampInMillis = number_format($currentTimestampInMillis, 0, '', '');
//        }
//        $stringToHash = $customerKey . $currentTimestampInMillis . $apiKey;
//        $authHeader = hash("sha512", $stringToHash);
//
//        $header = array (
//            "Content-Type: application/json",
//            "Customer-Key: $customerKey",
//            "Timestamp: $currentTimestampInMillis",
//            "Authorization: $authHeader"
//        );
//        return $header;
//    }
//
//    function send_otp_token($email, $phone, $sendToEmail = TRUE, $sendToPhone = FALSE){
//        $url = get_option('host_name') . '/moas/api/auth/challenge';
//
//        $customerKey =  $this->defaultCustomerKey;
//        $apiKey =  $this->defaultApiKey;
//
//        $username = get_option('mo_oauth_admin_email');
//        $phone=get_option('mo_oauth_admin_phone');
//        /* Current time in milliseconds since midnight, January 1, 1970 UTC. */
//        $currentTimeInMillis = self::get_timestamp();
//
//        /* Creating the Hash using SHA-512 algorithm */
//        $stringToHash = $customerKey . $currentTimeInMillis . $apiKey;
//        $hashValue = hash("sha512", $stringToHash);
//
//        $customerKeyHeader = "Customer-Key: " . $customerKey;
//        $timestampHeader = "Timestamp: " . $currentTimeInMillis;
//        $authorizationHeader = "Authorization: " . $hashValue;
//
//        if($sendToEmail){
//            $fields = array(
//                'customerKey' => $customerKey,
//                'email' => $username,
//                'authType' => 'EMAIL',
//            );}
//        else{
//            $fields=array(
//                'customerKey'=>$customerKey,
//                'phone' => $phone,
//                'authType' => 'SMS');
//        }
//        $field_string = json_encode($fields);
//
//        $headers = array( 'Content-Type' => 'application/json');
//        $headers['Customer-Key'] = $customerKey;
//        $headers['Timestamp'] = $currentTimeInMillis;
//        $headers['Authorization'] = $hashValue;
//        $args = array(
//            'method' =>'POST',
//            'body' => $field_string,
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//
//        return wp_remote_retrieve_body($response);
//    }
//
//    public function get_timestamp() {
//        $url = get_option ( 'host_name' ) . '/moas/rest/mobile/get-timestamp';
//        $headers = array( 'Content-Type' => 'application/json', 'charset' => 'UTF - 8', 'Authorization' => 'Basic' );
//        $args = array(
//            'method' =>'POST',
//            'body' => array(),
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//
//        return wp_remote_retrieve_body($response);
//    }
//

//    function validate_otp_token($transactionId,$otpToken){
//        $url = get_option('host_name') . '/moas/api/auth/validate';
//
//
//        $customerKey =  $this->defaultCustomerKey;
//        $apiKey =  $this->defaultApiKey;
//
//        $username = get_option('mo_oauth_admin_email');
//
//        /* Current time in milliseconds since midnight, January 1, 1970 UTC. */
//        $currentTimeInMillis = self::get_timestamp();
//
//        /* Creating the Hash using SHA-512 algorithm */
//        $stringToHash = $customerKey . $currentTimeInMillis . $apiKey;
//        $hashValue = hash("sha512", $stringToHash);
//
//        $customerKeyHeader = "Customer-Key: " . $customerKey;
//        $timestampHeader = "Timestamp: " . $currentTimeInMillis;
//        $authorizationHeader = "Authorization: " . $hashValue;
//
//        $fields = '';
//
//        //*check for otp over sms/email
//        $fields = array(
//            'txId' => $transactionId,
//            'token' => $otpToken,
//        );
//
//        $field_string = json_encode($fields);
//
//        $headers = array( 'Content-Type' => 'application/json');
//        $headers['Customer-Key'] = $customerKey;
//        $headers['Timestamp'] = $currentTimeInMillis;
//        $headers['Authorization'] = $hashValue;
//        $args = array(
//            'method' =>'POST',
//            'body' => $field_string,
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//
//        return wp_remote_retrieve_body($response);
//    }

//    function mo_oauth_send_email_alert($email,$phone,$message,$subject){
//
//        if(!$this->check_internet_connection())
//            return;
//        $url = get_option( 'host_name' ) . '/moas/api/notify/send';
//
//
//        $customerKey = $this->defaultCustomerKey;
//        $apiKey =  $this->defaultApiKey;
//
//        $currentTimeInMillis = self::get_timestamp();
//        $stringToHash 		= $customerKey .  $currentTimeInMillis . $apiKey;
//        $hashValue 			= hash("sha512", $stringToHash);
//        $customerKeyHeader 	= "Customer-Key: " . $customerKey;
//        $timestampHeader 	= "Timestamp: " .  $currentTimeInMillis;
//        $authorizationHeader= "Authorization: " . $hashValue;
//        $fromEmail 			= $email;
//        //$subject            = "Feedback: WordPress OAuth Client Plugin";
//        $site_url=site_url();
//
//        global $user;
//        $user         = wp_get_current_user();
//        $query        = '[WP OAuth Single Sign On - SSO] : ' . $message;
//
//        $content='<div >Hello, <br><br>First Name :'.$user->user_firstname.'<br><br>Last  Name :'.$user->user_lastname.'   <br><br>Company :<a href="'.$_SERVER['SERVER_NAME'].'" target="_blank" >'.$_SERVER['SERVER_NAME'].'</a><br><br>Phone Number :'.$phone.'<br><br>Email :<a href="mailto:'.$fromEmail.'" target="_blank">'.$fromEmail.'</a><br><br>Query :'.$query.'</div>';
//
//        $fields = array(
//            'customerKey'	=> $customerKey,
//            'sendEmail' 	=> true,
//            'email' 		=> array(
//                'customerKey' 	=> $customerKey,
//                'fromEmail' 	=> $fromEmail,
//                'bccEmail' 		=> 'oauthsupport@xecurify.com',
//                'fromName' 		=> 'miniOrange',
//                'toEmail' 		=> 'oauthsupport@xecurify.com',
//                'toName' 		=> 'oauthsupport@xecurify.com',
//                'subject' 		=> $subject,
//                'content' 		=> $content
//            ),
//        );
//        $field_string = json_encode($fields);
//        $headers = array( 'Content-Type' => 'application/json');
//        $headers['Customer-Key'] = $customerKey;
//        $headers['Timestamp'] = $currentTimeInMillis;
//        $headers['Authorization'] = $hashValue;
//        $args = array(
//            'method' =>'POST',
//            'body' => $field_string,
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//    }

//    function mo_oauth_send_demo_alert($email,$demo_plan,$message,$subject) {
//
//        if(!$this->check_internet_connection())
//            return;
//        $url = get_option( 'host_name' ) . '/moas/api/notify/send';
//
//        $customerKey = $this->defaultCustomerKey;
//        $apiKey =  $this->defaultApiKey;
//
//        $currentTimeInMillis = self::get_timestamp();
//        $stringToHash 		= $customerKey .  $currentTimeInMillis . $apiKey;
//        $hashValue 			= hash("sha512", $stringToHash);
//        $customerKeyHeader 	= "Customer-Key: " . $customerKey;
//        $timestampHeader 	= "Timestamp: " .  $currentTimeInMillis;
//        $authorizationHeader= "Authorization: " . $hashValue;
//        $fromEmail 			= $email;
//        $site_url=site_url();
//
//        global $user;
//        $user         = wp_get_current_user();
//
//        $content='<div >Hello, </a><br><br>Email :<a href="mailto:'. $fromEmail.'" target="_blank">'.$fromEmail.'</a><br><br>Requested Demo for     : ' . $demo_plan . '<br><br>Requirements (User usecase)           : ' . $message.'</div>';
//
//        $fields = array(
//            'customerKey'	=> $customerKey,
//            'sendEmail' 	=> true,
//            'email' 		=> array(
//                'customerKey' 	=> $customerKey,
//                'fromEmail' 	=> $fromEmail,
//                'bccEmail' 		=> 'oauthsupport@xecurify.com',
//                'fromName' 		=> 'miniOrange',
//                'toEmail' 		=> 'oauthsupport@xecurify.com',
//                'toName' 		=> 'oauthsupport@xecurify.com',
//                'subject' 		=> $subject,
//                'content' 		=> $content
//            ),
//        );
//        $field_string = json_encode($fields);
//        $headers = array( 'Content-Type' => 'application/json');
//        $headers['Customer-Key'] = $customerKey;
//        $headers['Timestamp'] = $currentTimeInMillis;
//        $headers['Authorization'] = $hashValue;
//        $args = array(
//            'method' =>'POST',
//            'body' => $field_string,
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//    }

//    function mo_oauth_forgot_password($email) {
//        $url = get_option ( 'host_name' ) . '/moas/rest/customer/password-reset';
//        /* The customer Key provided to you */
//        $customerKey = get_option ( 'mo_oauth_admin_customer_key' );
//
//        /* The customer API Key provided to you */
//        $apiKey = get_option ( 'mo_oauth_admin_api_key' );
//
//        /* Current time in milliseconds since midnight, January 1, 1970 UTC. */
//        $currentTimeInMillis = self::get_timestamp();
//
//        /* Creating the Hash using SHA-512 algorithm */
//        $stringToHash = $customerKey . $currentTimeInMillis . $apiKey;
//        $hashValue = hash ( "sha512", $stringToHash );
//
//        $customerKeyHeader = "Customer-Key: " . $customerKey;
//        $timestampHeader = "Timestamp: " . number_format ( $currentTimeInMillis, 0, '', '' );
//        $authorizationHeader = "Authorization: " . $hashValue;
//
//        $fields = '';
//
//        // *check for otp over sms/email
//        $fields = array (
//            'email' => $email
//        );
//
//        $field_string = json_encode ( $fields );
//
//        $headers = array( 'Content-Type' => 'application/json');
//        $headers['Customer-Key'] = $customerKey;
//        $headers['Timestamp'] = $currentTimeInMillis;
//        $headers['Authorization'] = $hashValue;
//        $args = array(
//            'method' =>'POST',
//            'body' => $field_string,
//            'timeout' => '5',
//            'redirection' => '5',
//            'httpversion' => '1.0',
//            'blocking' => true,
//            'headers' => $headers,
//
//        );
//
//        $response = wp_remote_post( $url, $args );
//        if ( is_wp_error( $response ) ) {
//            $error_message = $response->get_error_message();
//            echo "Something went wrong: $error_message";
//            exit();
//        }
//
//        return wp_remote_retrieve_body($response;
//    }

    function check_internet_connection() {
        return (bool) @fsockopen('login.xecurify.com', 443, $iErrno, $sErrStr, 5);
    }

    function prepareCurlOptions($url, $field_string){
        $ch = curl_init($url);
        curl_setopt ( $ch, CURLOPT_FOLLOWLOCATION, true );
        curl_setopt ( $ch, CURLOPT_ENCODING, "" );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_AUTOREFERER, true );
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false ); // required for https urls
        curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
        curl_setopt ( $ch, CURLOPT_MAXREDIRS, 10 );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $field_string );

        return $ch;
    }

}