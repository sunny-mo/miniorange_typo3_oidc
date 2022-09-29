<?php

namespace Miniorange\MiniorangeOidc\Controller;

use Miniorange\Helper\Constants;
use Miniorange\Helper\MoUtilities;
use Miniorange\MiniorangeOidc\Domain\Model\Feoidc;
use Miniorange\MiniorangeOidc\Domain\Repository\FeoidcRepository;

use PDO;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Extbase\Object\ObjectManager;


/**
 * FeoidcController
 */
class FeoidcController extends ActionController
{

    protected $feoidcRepository = null;

    /**
     * 
     * @return void
     * @throws Exception
     */
    public function requestAction()
    {
        error_log("In FeoidcController : sendRequestAction()");
       GeneralUtility::makeInstance(\TYPO3\CMS\Core\Cache\CacheManager::class)->flushCaches();
        
        //$samlRequest = $this->build();
        if(isset($_GET['RelayState']))
        {
            $cookkey="mo_oauth_test";
            $cookval=true;
            setcookie($cookkey,$cookval);
        }
        $relayState = isset($_REQUEST['RelayState']) ? $_REQUEST['RelayState'] : '/';
        if ($this->findSubstring($_REQUEST) == 1) {
            $relayState = 'testconfig';
        }

        $auth_url = $this->createAuthorizationUrl();

        header('Location: ' . $auth_url);
    }

    /**
     * @param $request
     * @return int
     */
    private function findSubstring($request)
    {
        if (!empty($request["id"]) and strpos($request["id"], 'RelayState') !== false) {
            return 1;
        } else {
            return 0;
        }
    }

    private function createAuthorizationUrl(){
        error_log("In FeoidcConroller : createAuthorizationUrl()");

        $json_object = MoUtilities::fetchFromDb(Constants::OIDC_OIDC_OBJECT,Constants::TABLE_OIDC);
        $app = json_decode($json_object,true);
        if(empty($app))
        {
            echo "Please configure the plugin first!!!";exit;
        }
        $state = base64_encode($app[Constants::OIDC_APP_NAME]);
        $authorizationUrl = $app[Constants::OIDC_AUTH_URL];

        if(strpos($authorizationUrl, "google") !== false) {
            $authorizationUrl = "https://accounts.google.com/o/oauth2/auth";
        }

        if(strpos($authorizationUrl, '?' ) !== false)
            $authorizationUrl = $authorizationUrl."&client_id=".$app[Constants::OIDC_CLIENT_ID]."&scope=".$app[Constants::OIDC_SCOPE]."&redirect_uri=".$app[Constants::OIDC_REDIRECT_URL]."&response_type=code&state=".$state;
        else
            $authorizationUrl = $authorizationUrl."?client_id=".$app[Constants::OIDC_CLIENT_ID]."&scope=".$app[Constants::OIDC_SCOPE]."&redirect_uri=".$app[Constants::OIDC_REDIRECT_URL]."&response_type=code&state=".$state;

        if(session_id() == '' || !isset($_SESSION))
            session_start();
        $_SESSION['oauth2state'] = $state;
        $_SESSION['appname'] = $app[Constants::OIDC_APP_NAME];

       return $authorizationUrl;
    }

    //here entity is corporation, alliance or character name. The administrator compares these when user logs in
    function moAuthCheckValidityOfEntity($entityValue, $entitySessionValue, $entityName) {

        $entityString = $entityValue ? $entityValue : false;
        $valid_entity = false;
        if( $entityString ) {			//checks if entityString is defined
            if ( strpos( $entityString, ',' ) !== false ) {			//checks if there are more than 1 entity defined
                $entity_list = array_map( 'trim', explode( ",", $entityString ) );
                foreach( $entity_list as $entity ) {			//checks for each entity to exist
                    if( $entity == $entitySessionValue ) {
                        $valid_entity = true;
                        break;
                    }
                }
            } else {		//only one entity is defined
                if( $entityString == $entitySessionValue ) {
                    $valid_entity = true;
                }
            }
        } else {			//entity is not defined
            $valid_entity = false;
        }
        return $valid_entity;
    }

    function testAttrMappingConfig($nestedprefix, $resourceOwnerDetails){
        error_log("In FeoidcController : testAttrMappingConfig()");
        foreach($resourceOwnerDetails as $key => $resource){
            if(is_array($resource) || is_object($resource)){
                if(!empty($nestedprefix))
                    $nestedprefix .= ".";
                $this->testattrmappingconfig($nestedprefix.$key,$resource);
                $nestedprefix = rtrim($nestedprefix,".");
            } else {
                echo "<tr><td>";
                if(!empty($nestedprefix))
                    echo $nestedprefix.".";
                echo $key."</td><td>".$resource."</td></tr>";
            }
        }
    }

    function getNestedAttribute($resource, $key){
        if($key==="")
            return "";

        $keys = explode(".",$key);
        if(sizeof($keys)>1){
            $current_key = $keys[0];
            if(isset($resource[$current_key]))
                return getnestedattribute($resource[$current_key], str_replace($current_key.".","",$key));
        } else {
            $current_key = $keys[0];
            if(isset($resource[$current_key])) {
                return $resource[$current_key];
            }
        }
    }

    function mo_oauth_jkhuiysuayhbw($ejhi)
    {
        $option = 0; $flag = false;
        $mo_oauth_authorizations = get_option('mo_oauth_authorizations');
        if(!empty($mo_oauth_authorizations))
            $option = get_option( 'mo_oauth_authorizations' );
        $user = mo_oauth_hjsguh_kiishuyauh878gs($ejhi);
        if($user);
        ++$option;
        update_option( 'mo_oauth_authorizations', $option);
        if($option >= 10)
        {
            $mo_oauth_set_val = base64_decode('bW9fb2F1dGhfZmxhZw==');
            update_option($mo_oauth_set_val, true);
        }
        return $user;
    }

    function mo_oauth_jhuyn_jgsukaj($temp_var)
    {
        return mo_oauth_jkhuiysuayhbw($temp_var);
    }

}
