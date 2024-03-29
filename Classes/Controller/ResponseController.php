<?php


namespace Miniorange\MiniorangeOidc\Controller;

use Miniorange\Helper\Constants;
use Miniorange\Helper\MoUtilities;
use Miniorange\Helper\Utilities;
use Miniorange\Helper\OAuthHandler;
use Miniorange\MiniorangeOidc\Domain\Repository\ResponseRepository;
use Miniorange\Helper\Actions\TestResultActions;

use ReflectionClass;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Database\ConnectionPool;
use \TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Felogin\Controller\FrontendLoginController;
use TYPO3\CMS\Extbase\Domain\Model\FrontendUser;
use TYPO3\CMS\Extbase\Domain\Repository\FrontendUserRepository;
use TYPO3\CMS\Frontend\Authentication\FrontendUserAuthentication;

/**
 * ResponseController
 */
class ResponseController extends ActionController
{
//    /**
//     * responseRepository
//     *
//     * @var ResponseRepository
//     * @inject
//     */
//    protected $responseRepository = null;
//
//    protected $fesamlRepository = null;

//    protected $idp_name = null;
//
//    protected $acs_url = null;
//
//    protected $sp_entity_id = null;
//
//    protected $force_authn = null;
//
//    protected $saml_login_url = null;
//
//    private $issuer = null;
//
//    private $ssoUrl = null;
//
//    private $bindingType = null;
//
//    private $signedAssertion = null;
//
//    private $signedResponse = null;
//
//    private $ssoemail = null;

    private $first_name = null;
    private $last_name = null;
    protected $persistenceManager = null;
    protected $frontendUserRepository = null;
    private $ses_id = null;

    // /**
    //  * @inject
    //  * @param FrontendUserRepository $frontendUserRepository
    //  */
    // public function injectFrontendUserRepository(FrontendUserRepository $frontendUserRepository)
    // {
    //     $this->frontendUserRepository = $frontendUserRepository;
    // }

    function testattrmappingconfig($nestedprefix, $resourceOwnerDetails){
        error_log("In ResponseController : testattrmappingconfig()");
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
    /**
     * action check
     *
     * @return void
     */
    public function responseAction()
    {
        error_log("In reponseController: checkAction() ");

       GeneralUtility::makeInstance(\TYPO3\CMS\Core\Cache\CacheManager::class)->flushCaches();
        if (strpos($_SERVER['REQUEST_URI'], "/oauthcallback") !== false || isset($_GET['code'])) {
            if (session_id() == '' || !isset($_SESSION))
                session_start();

                error_log("session started".print_r($_SERVER,true));
            // OAuth state security check
            /*
            if (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
                if (isset($_SESSION['oauth2state'])) {
                    unset($_SESSION['oauth2state']);
                }
                exit('Invalid state');
            } */

            error_log("code: ".print_r($_GET,true));
            if (!isset($_GET['code'])) {
                if (isset($_GET['error_description']))
                    exit($_GET['error_description']);
                else if (isset($_GET['error']))
                    exit($_GET['error']);
                exit('Invalid response');
            } else {

                try {

                    $currentappname = "";

                    if (isset($_SESSION['appname']) && !empty($_SESSION['appname']))
                        $currentappname = $_SESSION['appname'];
                    else if (isset($_GET['state']) && !empty($_GET['state'])) {
                        $currentappname = base64_decode($_GET['state']);
                    }
                    if (empty($currentappname)) {
                        exit('No request found for this application.');
                    }

                    $username_attr = "";

                    $attr_map = json_decode(MoUtilities::fetchFromDb('am_object',Constants::TABLE_OIDC),true);

                    $am_username = MoUtilities::fetchFromDb(Constants::OIDC_ATTRIBUTE_USERNAME, Constants::TABLE_OIDC);
                    $currentapp = json_decode(MoUtilities::fetchFromDb('oidc_object', Constants::TABLE_OIDC), true);
                    if (isset( $am_username) &&  $am_username != "") {
                        $username_attr = $am_username;
                    } else if (isset($app['email_attr']) && $app["email_attr"] != "") {
//                        mo_oauth_update_email_to_username_attr($currentappname);
                        $username_attr = $attr_map['email_attr'];
                        exit("Attribute Mapping not configured.");
                    }

                    if(!$currentapp)
                        exit('Application not configured.');

                    $mo_oauth_handler = new OAuthHandler();

                    if (!isset($currentapp['set_header_credentials']))
                        $currentapp['set_header_credentials'] = false;
                    if (!isset($currentapp['set_body_credentials']))
                        $currentapp['set_body_credentials'] = false;

                    if (isset($currentapp['app_type']) && $currentapp['app_type'] == Constants::TYPE_OPENID_CONNECT) {
                        // OpenId connect

                        $relayStateUrl = array_key_exists('RelayState', $_REQUEST) ? $_REQUEST['RelayState'] : '/';
                     //   $relayStateUrl='testconfig';
                        error_log("relaystate in response: ".$relayStateUrl);
                        $tokenResponse = $mo_oauth_handler->getIdToken($currentapp['token_endpoint'],
                            'authorization_code',
                            $currentapp['client_id'],
                            $currentapp['client_secret'],
                            $_GET['code'],
                            $currentapp['redirect_url'],
                            $currentapp['set_header_credentials'],
                            $currentapp['set_body_credentials']
                        );

                        $idToken = isset($tokenResponse["id_token"]) ? $tokenResponse["id_token"] : $tokenResponse["access_token"];

                        if (!$idToken)
                            exit('Invalid token received.');
                        else
                            $resourceOwner = $mo_oauth_handler->getResourceOwnerFromIdToken($idToken);
                            $resourceOwner['NameID']= ['0' => $resourceOwner['email'] ?: $resourceOwner['mail']];
                    } else {
                        // echo "OAuth";
                        $accessTokenUrl = $currentapp['token_url'];
                        if (strpos($accessTokenUrl, "google") !== false) {
                            $accessTokenUrl = "https://www.googleapis.com/oauth2/v4/token";
                        }

                        $accessToken = $mo_oauth_handler->getAccessToken($accessTokenUrl,
                           'authorization_code',
                            $currentapp['clientid'],
                            $currentapp['clientsecret'],
                            $_GET['code'],
                            $currentapp['redirecturi'],
                            $currentapp['send_headers'],
                            $currentapp['send_body']
                        );

                        if (!$accessToken)
                            exit('Invalid token received.');

                        $resourceownerdetailsurl = $currentapp['resourceownerdetailsurl'];
                        if (substr($resourceownerdetailsurl, -1) == "=") {
                            $resourceownerdetailsurl .= $accessToken;
                        }
                        if (strpos($resourceownerdetailsurl, "google") !== false) {
                            $resourceownerdetailsurl = "https://www.googleapis.com/oauth2/v1/userinfo";
                        }
                        $resourceOwner = $mo_oauth_handler->getResourceOwner($resourceownerdetailsurl, $accessToken);
                    }

                    $username = "";
                    
                    //TEST Configuration
                    if (isset($_COOKIE['mo_oauth_test']) && $_COOKIE['mo_oauth_test']) {
                        echo '<div style="font-family:Calibri;padding:0 3%;">';
                        echo '<style>table{border-collapse:collapse;}th {background-color: #eee; text-align: center; padding: 8px; border-width:1px; border-style:solid; border-color:#212121;}tr:nth-child(odd) {background-color: #f2f2f2;} td{padding:8px;border-width:1px; border-style:solid; border-color:#212121;}</style>';
                        (new TestResultActions($resourceOwner))->execute();
                        setcookie('mo_oauth_test',false);
                        exit();
                    }

                    if (!empty($username_attr))
                        $username = $this->getnestedattribute($resourceOwner, $username_attr); //$resourceOwner[$email_attr];
                        
                    if (empty($username) || "" === $username)
                        exit('Username not received. Check your <b>Attribute Mapping</b> configuration.');
                    if (!is_string($username['0'])) {
                        exit('Username is not a string. It is ' . gettype($username));
                    }
                } catch (Exception $e) {
                    // Failed to get the access token or user details.
                    //print_r($e);
                    exit($e->getMessage());
                }
            }
            if(is_array($username))
            $this->login_user($username['0']);
            else
            $this->login_user($username);
        }


        else if (isset($_REQUEST['option']) and strpos($_REQUEST['option'], 'mooauth') !== false) {
            //do stuff after returning from oAuth processing
            $access_token = $_POST['access_token'];
            $token_type = $_POST['token_type'];
            $user_email = '';
            if (array_key_exists('email', $_POST))
                $user_email = $_POST['email'];

            $this->login_user($user_email);
        }
    }


    function login_user($username){

        error_log("In ResponseController : login_user()");
        $this->ssoemail = $username ;

        $username = $this->ssoemail;
        $GLOBALS['TSFE']->fe_user->checkPid = 0;
        $info = $GLOBALS['TSFE']->fe_user->getAuthInfoArray();
        $user = Utilities::fetchUserFromUsername($username);
        if ($user == null) {
            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
            $count = $queryBuilder->select('countuser')->from(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, \PDO::PARAM_INT)))->execute()->fetchColumn(0);
            if($count>0)
            {
                $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, \PDO::PARAM_INT)))->set('countuser', $count-1)->execute();
            $user = $this->create($username);
            }
            else{
                echo "Auto create user limit exceeded...Please upgrade to the premium version";exit;
            }
            $user = Utilities::fetchUserFromUsername($username);
        }
        $GLOBALS['TSFE']->fe_user->forceSetCookie = TRUE;
        $GLOBALS['TSFE']->fe_user->loginUser = 1;
        $GLOBALS['TSFE']->fe_user->start();
        $GLOBALS['TSFE']->fe_user->createUserSession($user);
        $GLOBALS['TSFE']->initUserGroups();
        $GLOBALS['TSFE']->fe_user->loginSessionStarted = TRUE;
        $GLOBALS['TSFE']->fe_user->user = $user;
        $GLOBALS['TSFE']->fe_user->setKey('user', 'fe_typo_user', $user);
        $GLOBALS['TSFE']->fe_user->setKey('ses', 'fe_typo_user', $user);
        $GLOBALS['TSFE']->fe_user->user = $GLOBALS['TSFE']->fe_user->fetchUserSession();
        $GLOBALS['TSFE']->fe_user->setAndSaveSessionData('user', TRUE);
        $this->ses_id = $GLOBALS['TSFE']->fe_user->fetchUserSession();
        //echo print_r($this->ses_id,true);exit;
        // $GLOBALS['TSFE']->fe_user->setKey('user', 'ses_id', $this->ses_id);
        // $session = $GLOBALS['TSFE']->fe_user->user['ses_id'];
        // setcookie('fe_typo_user', $session, NULL, "/");
        $reflection = new ReflectionClass($GLOBALS['TSFE']->fe_user);
        $setSessionCookieMethod = $reflection->getMethod('setSessionCookie');
        $setSessionCookieMethod->setAccessible(TRUE);
        $setSessionCookieMethod->invoke($GLOBALS['TSFE']->fe_user);
        $GLOBALS['TYPO3_CONF_VARS']['SVCONF']['auth']['setup']['FE_alwaysFetchUser'] = true;
        $GLOBALS['TYPO3_CONF_VARS']['SVCONF']['auth']['setup']['FE_alwaysAuthUser'] = true;
        $GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['felogin']['login_confirmed'] = true;
        $GLOBALS['TSFE']->fe_user->storeSessionData();
        $test = $GLOBALS['TSFE']->fe_user->user;
        if (!isset($_SESSION)) {
            session_id('email');
            session_start();
            $_SESSION['email'] = $this->ssoemail;
            $_SESSION['id'] = $this->ses_id;
        }
//            $actual_link = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
        $actual_link = MoUtilities::fetchFromDb(Constants::OIDC_REDIRECT_URL,Constants::TABLE_OIDC);
        \TYPO3\CMS\Core\Utility\HttpUtility::redirect($actual_link);
    }


    function getnestedattribute($resource, $key){
        error_log("In ResponseController : getnestedattribute()");
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

    function get_proper_prefix( $type ) {
        $letter = substr( $type, 0, 1 );
        $vowels = [ 'a', 'e', 'i', 'o', 'u' ];
        return ( in_array( $letter, $vowels ) ) ? ' an ' . $type : ' a ' . $type;
    }

    //here entity is corporation, alliance or character name. The administrator compares these when user logs in
    function mo_oauth_check_validity_of_entity($entityValue, $entitySessionValue, $entityName) {

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


    
    function fetch_fname()
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $fname = $queryBuilder->select('oidc_am_fname')->from(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, \PDO::PARAM_INT)))->execute()->fetchColumn(0);
        return $fname;
    }

    function fetch_lname()
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $lname = $queryBuilder->select('oidc_am_lname')->from(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, \PDO::PARAM_INT)))->execute()->fetchColumn(0);
        return $lname;
    }

    /**
     * @param $val
     */
    function setFlag($val)
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, \PDO::PARAM_INT)))->set('custom_attr', $val)->execute();
    }

    /**
     * @param $ses_id
     * @param $ssoemail
     * @return string
     * @throws \Exception
     */
    function logout($ses_id)
    {
        error_log("In ResponseController : logout()");
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);

        if (session_status() == PHP_SESSION_NONE) {
            session_id($ses_id);
            session_start();
        }

    }

    /**
     * @param $nameId
     * @param $sessionIndex
     * @param $issuer
     * @param $destination
     * @param $slo_binding_type
     * @return string
     */
    function createLogoutRequest($nameId, $sessionIndex = '', $issuer, $destination, $slo_binding_type = 'HttpRedirect')
    {
        return;
// $requestXmlStr;
    }

	/**
	 * @param $username
	 * @return FrontendUser
	 */
    function create($username)
    {
        $fname_lname = explode('@',$username);
        $first_name = $fname_lname['0'];
        $last_name = $fname_lname['1'];
        $this->objectManager = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');

        $objectManager = GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');
        $frontendUser = new FrontendUser();
        $frontendUser->setUsername($username);
        $frontendUser->setFirstName($first_name);
        $frontendUser->setLastName($last_name);
        $frontendUser->setEmail($username);
        $frontendUser->setPassword('demouser');
        $mappedGroupUid = Utilities::fetchUidFromGroupName(Utilities::fetchFromTable(Constants::COLUMN_GROUP_DEFAULT,Constants::TABLE_OIDC));
        $userGroup = $this->objectManager->get('TYPO3\\CMS\\Extbase\\Domain\\Repository\\FrontendUserGroupRepository')->findByUid($mappedGroupUid);
        //$userGroup = $this->objectManager->get('TYPO3\\CMS\\Extbase\\Domain\\Repository\\FrontendUserGroupRepository')->findByUid(1);


        $frontendUser->addUsergroup($userGroup);

        $this->frontendUserRepository = $objectManager->get('TYPO3\\CMS\\Extbase\\Domain\\Repository\\FrontendUserRepository')->add($frontendUser);
        $this->persistenceManager = $objectManager->get('TYPO3\\CMS\\Extbase\\Persistence\\Generic\\PersistenceManager')->persistAll();
        return $frontendUser;
    }

    function control()
    {
      
    }

    /**
     * @param $instant
     * @return false|string
     */
    function generateTimestamp($instant = NULL)
    {
        if ($instant === NULL) {
            $instant = time();
        }
        return gmdate('Y-m-d\\TH:i:s\\Z', $instant);
    }

    function generateID()
    {
        return '_' . $this->stringToHex($this->generateRandomBytes(21));
    }

    /**
     * @param $bytes
     * @return string
     */
    function stringToHex($bytes)
    {
        $ret = '';
        for ($i = 0; $i < strlen($bytes); $i++) {
            $ret .= sprintf('%02x', ord($bytes[$i]));
        }
        return $ret;
    }

    /**
     * @param $length
     * @param $fallback
     * @return false|string
     */
    function generateRandomBytes($length, $fallback = TRUE)
    {
        return openssl_random_pseudo_bytes($length);
    }  
}