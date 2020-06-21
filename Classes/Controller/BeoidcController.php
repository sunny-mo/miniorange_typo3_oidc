<?php

namespace Miniorange\MiniorangeOidc\Controller;

use Exception;

use Miniorange\MiniorangeOidc\Domain\Model\Beoidc;
use Miniorange\Helper\MoUtilities;
use Miniorange\Helper\CustomerMo;
use Miniorange\Helper\Constants;

use PDO;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Tstemplate\Controller\TypoScriptTemplateModuleController;
use TYPO3\CMS\Extbase\Object\ObjectManager;

/**
 *BeoidcController
 */
class BeoidcController extends ActionController
{
    /**
     * beoidcRepository
     *
     * @var \Miniorange\MiniorangeOidc\Domain\Repository\BeoidcRepository
     * @inject
     */
    public $beoidcRepository = null;

    private $myjson = null;

    private $myattrjson = null;

    private $custom_attr = null;

    private $spobject = null;

    protected $sp_entity_id = null;

    protected $site_base_url = null;

    protected $acs_url = null;

    protected $slo_url = null;

    protected $fesaml = null;

    protected $response = null;

    protected $tab = "";

//    /**
//     * action list
//     *
//     * @return void
//     */
//    public function listAction()
//    {
//        $besamls = $this->besamlRepository->findAll();
//        $this->view->assign('besamls', $besamls);
//    }
//
//    /**
//     * action show
//     *
//     * @param Besaml $besaml
//     * @return void
//     */
//    public function showAction(Besaml $besaml)
//    {
//        $this->view->assign('besaml', $besaml);
//    }

    /**
     * @throws Exception
     */
    public function requestAction()
    {

        error_log("inside showAction : BeoidcController : ");
        error_log("REQUEST : ".$_POST['option']);

//------------ IDENTITY PROVIDER SETTINGS---------------
        if(isset($_POST['option']) and $_POST['option']=="oidc_settings"){

            error_log("Received OIDC Settings: " );

//            $value1 = $this->validateURL($_POST['saml_login_url']);
//            $value2 = $this->validateURL($_POST['idp_entity_id']);
//            $value3 = MoUtilities::check_certificate_format($_POST['x509_certificate']);
//            $value4 = $this->validateURL($_POST['saml_logout_url']);
//            error_log("Check_certificate_format: ".$value3);
                $this->storeToDatabase($_POST);
//            if($value1 == 1 && $value2 == 1 && $value3 == 1 && $value4 = 1)
//            {
//                $obj = new BeoidcController();
//                $obj->storeToDatabase($_POST);
//                MoUtilities::showSuccessFlashMessage('IdP Setting saved successfully.');
//            }else{
//                if ($value3 == 0) {
//                    MoUtilities::showErrorFlashMessage('Incorrect Certificate Format');
//                }else {
//                    MoUtilities::showErrorFlashMessage('Blank Field or Invalid input');
//                }
//            }
        }

//------------ HANDLING SUPPORT QUERY---------------
        if ( isset( $_POST['option'] ) and $_POST['option'] == "mo_saml_contact_us_query_option" ) {
            error_log('Received support query.  ');
            $this->support();
        }

//------------ VERIFY CUSTOMER---------------
        if ( isset( $_POST['option'] ) and $_POST['option'] == "mo_saml_verify_customer" ) {
            error_log('Received verify customer request(login). ');

            if($_POST['registered'] =='isChecked'){
                error_log("registered is checked. Registering User : ");
                $this->account($_POST);
            }else{
                if($_POST['password'] == $_POST['confirmPassword']){
                    $this->account($_POST);
//                    error_log("both passwords are equal.");
                }else{
                    MoUtilities::showErrorFlashMessage('Please enter same password in both password fields.');
                    error_log("both passwords are not same.");
                }
            }

        }

//------------ HANDLE LOG OUT ACTION---------------
        if(isset($_POST['option'])){
//					error_log("inside option ");
            if ($_POST['option']== 'logout') {
                error_log('Received log out request.');
                $this->remove_cust();
                MoUtilities::showSuccessFlashMessage('Logged out successfully.');
            }
            $this->view->assign('status','not_logged');
        }

//------------ SERVICE PROVIDER SETTINGS---------------
        if (isset( $_POST['option'] ) and $_POST['option'] == "attribute_mapping"){

            $usrename = $_POST['oidc_am_username'];

            if(!MoUtilities::isEmptyOrNull($usrename))
            {
                if($this->fetchFromOidc('uid') == null){
                    MoUtilities::showErrorFlashMessage('Please configure OpenIDConnect client first.');
                }else{
                    $tempAmObj = json_encode($_POST);
                    $this->save('oidc_am_username',$usrename,Constants::OIDC_TABLE);
                    $this->save('am_obect',$tempAmObj,Constants::OIDC_TABLE);
                    MoUtilities::showSuccessFlashMessage('Attribute Mapping saved successfully.');
                }
            }else{
                MoUtilities::showErrorFlashMessage('Please provide valid input.');
            }
        }

//------------ CHANGING TABS---------------
        if($_POST['option'] == 'save_sp_settings' )
        {
            $this->tab = "Service_Provider";
        }
        elseif ($_POST['option'] == 'mo_saml_verify_customer')
        {
            $this->tab = "Account";

        }
        elseif ($_POST['option'] == 'save_connector_settings')
        {
            $this->tab = "Identity_Provider";
        }
        elseif ($_POST['option'] == 'attribute_mapping')
        {
            $this->tab = "Attribute_Mapping";
        }
        elseif ($_POST['option'] == 'mo_saml_contact_us_query_option')
        {
            $this->tab = "Support";
        }

//------------ LOADING SAVED SETTINGS OBJECTS TO BE USED IN VIEW---------------
        $this->view->assign('conf', json_decode($this->fetchFromOidc('oidc_object'), true));
        $this->view->assign('conf_am', json_decode($this->fetchFromOidc('am_object'), true));

//------------ LOADING VARIABLES TO BE USED IN VIEW---------------
        if($this->fetchFromCustomer('cust_reg_status') == 'logged'){
            $this->view->assign('status','logged');
            $this->view->assign('log', '');
            $this->view->assign('nolog', 'display:none');
            $this->view->assign('email',$this->fetchFromCustomer('cust_email'));
            $this->view->assign('key',$this->fetchFromCustomer('cust_key'));
            $this->view->assign('token',$this->fetchFromCustomer('cust_token'));
            $this->view->assign('api_key',$this->fetchFromCustomer('cust_api_key'));
        }else{
            $this->view->assign('log', 'disabled');
            $this->view->assign('nolog', 'display:block');
            $this->view->assign('status','not_logged');
        }

        $this->view->assign('tab', $this->tab);
//        $this->view->assign('extPath', MoUtilities::getExtensionRelativePath());

        $caches = new TypoScriptTemplateModuleController();
        $caches->clearCache();
        $this->cacheService->clearPageCache([$GLOBALS['TSFE']->id]);
    }

    public function save($column,$value,$table)
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($table);
        $affectedRows = $queryBuilder->insert($table)->values([ $column => $value, ])->execute();
    }

//  LOGOUT CUSTOMER
    public function remove_cust(){
        $this->updateCustomer('cust_key','');
        $this->updateCustomer('cust_api_key','');
        $this->updateCustomer('cust_token','');
        $this->updateCustomer('cust_reg_status', '');
        $this->updateCustomer('cust_email','');

        $this->updateOidc('idp_name',"");
        $this->updateOidc('idp_entity_id',"");
        $this->updateOidc('saml_login_url',"");
        $this->updateOidc('saml_logout_url',"");
        $this->updateOidc('x509_certificate',"");
        $this->updateOidc('login_binding_type',"");
        $this->updateOidc('object',"");
    }

//    VALIDATE CERTIFICATE
    public function validate_cert($saml_x509_certificate)
    {
        error_log("saml_certificate : ".print_r($saml_x509_certificate,true));

        $certificate = openssl_x509_parse ( $saml_x509_certificate);

        error_log("parsed certificate : ".print_r($certificate,true));

        foreach( $certificate as $key => $value ) {
            if ( empty( $value ) ) {
                unset( $saml_x509_certificate[ $key ] );
                return 0;
            } else {
                $saml_x509_certificate[ $key ] = $this->sanitize_certificate( $value );
                if ( ! @openssl_x509_read( $saml_x509_certificate[ $key ] ) ) {
                    return 0;
                }
            }
        }

        if ( empty( $saml_x509_certificate ) ) {
            return 0;
        }

        return 1;
    }

//    VALIDATE URLS
    public function validateURL($url)
    {
        if (filter_var($url, FILTER_VALIDATE_URL)) {
            return 1;
        } else {
            return 0;
        }
    }

    public function mo_is_curl_installed() {
        if ( in_array( 'curl', get_loaded_extensions() ) ) {
            return 1;
        } else {
            return 0;
        }
    }

//   HANDLE LOGIN FORM
    public function account($post){
        $email = $post['email'];
        $password = $post['password'];
        $customer = new CustomerMo();
        $customer->email = $email;
        $this->updateCustomer('cust_email', $email);
        $check_content = json_decode($customer->check_customer($email,$password), true);

        if($check_content['status'] == 'CUSTOMER_NOT_FOUND'){
            $customer = new CustomerMo();
            error_log("CUSTOMER_NOT_FOUND.. Creating ...");
            $result = $customer->create_customer($email,$password);
            if($result['status']== 'SUCCESS' ){
                $key_content = json_decode($customer->get_customer_key($email,$password), true);
                if($key_content['status'] == 'SUCCESS'){
                    $this->saveCustomer($key_content,$email);
                    MoUtilities::showSuccessFlashMessage('User retrieved successfully.');
                }else{
                    MoUtilities::showErrorFlashMessage('It seems like you have entered the incorrect password');
                }
            }
        }elseif ($check_content['status'] == 'SUCCESS'){
            $key_content = json_decode($customer->get_customer_key($email,$password), true);

            if($key_content['status'] == 'SUCCESS'){
                $this->saveCustomer($key_content,$email);
                MoUtilities::showSuccessFlashMessage('User retrieved successfully.');
            }
            else{
                MoUtilities::showErrorFlashMessage('It seems like you have entered the incorrect password');
            }
        }
    }

//  SAVE CUSTOMER
    public function saveCustomer($content, $email){
        $this->updateCustomer('cust_key',$content['id']);
        $this->updateCustomer('cust_api_key',$content['apiKey']);
        $this->updateCustomer('cust_token',$content['token']);
        $this->updateCustomer('cust_reg_status', 'logged');
        $this->updateCustomer('cust_email',$email);
    }

// FETCH CUSTOMER
    public function fetchFromCustomer($col)
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::CUSTOMER_TABLE);
        $variable = $queryBuilder->select($col)->from(Constants::CUSTOMER_TABLE)->where($queryBuilder->expr()->eq('id', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->execute()->fetchColumn(0);
        return $variable;
    }

// ---- UPDATE CUSTOMER Details
    public function updateCustomer($column, $value)
    {
        if($this->fetchFromCustomer('id') == null)
        {
            $this->insertCustomerRow();
        }
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::CUSTOMER_TABLE);
        $queryBuilder->update(Constants::CUSTOMER_TABLE)->where($queryBuilder->expr()->eq('id', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set($column, $value)->execute();
    }

    // FETCH OIDC VALUES
    public function fetchFromOidc($col){
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::OIDC_TABLE);
        $variable = $queryBuilder->select($col)->from(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->execute()->fetchColumn(0);
        return $variable;
    }

// ---- UPDATE OIDC Settings
    public function updateOidc($column, $value)
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::OIDC_TABLE);
        $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set($column, $value)->execute();
    }

    public function insertCustomerRow()
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::CUSTOMER_TABLE);
        $affectedRows = $queryBuilder->insert(Constants::CUSTOMER_TABLE)->values([  'id' => '1' ])->execute();
    }

// --------------------SUPPORT QUERY---------------------
    public function support(){
        if(!$this->mo_is_curl_installed() ) {
            MoUtilities::showErrorFlashMessage('ERROR: <a href="http://php.net/manual/en/curl.installation.php" 
                       target="_blank">PHP cURL extension</a> is not installed or disabled. Query submit failed.');
            return;
        }
        // Contact Us query
        $email    = $_POST['mo_saml_contact_us_email'];
        $phone    = $_POST['mo_saml_contact_us_phone'];
        $query    = $_POST['mo_saml_contact_us_query'];

        $customer = new CustomerMo();

        if($this->mo_check_empty_or_null( $email ) || $this->mo_check_empty_or_null( $query ) ) {
            MoUtilities::showErrorFlashMessage('Please enter a valid Email address. ');
        }elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            MoUtilities::showErrorFlashMessage('Please enter a valid Email address. ');
        }else {
            $submitted = json_decode($customer->submit_contact( $email, $phone, $query ), true);
            if ( $submitted['status'] == 'SUCCESS' ) {
                MoUtilities::showSuccessFlashMessage('Support query sent ! We will get in touch with you shortly.');
            }else{
                MoUtilities::showErrorFlashMessage('Could not send query. Please try again later or mail us at info@xecurify.com');
            }
        }
    }

    /**
     * @param $col
     * @param string $table
     * @return bool|string
     */

    public function mo_check_empty_or_null($value ) {
        if( ! isset( $value ) || empty( $value ) ) {
            return true;
        }
        return false;
    }

    /**
     * @param $postArray
     */
    public function defaultSettings($postArray)
    {
        $this->spobject = json_encode($postArray);
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('saml');
        $queryBuilder->update('saml')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('sp_entity_id', $postArray['sp_entity_id'])->execute();
        $queryBuilder->update('saml')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('site_base_url', $postArray['site_base_url'])->execute();
        $queryBuilder->update('saml')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('acs_url', $postArray['acs_url'])->execute();
        $queryBuilder->update('saml')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('slo_url', $postArray['slo_url'])->execute();
        $queryBuilder->update('saml')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('fesaml', $postArray['fesaml'])->execute();
        $queryBuilder->update('saml')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('response', $postArray['response'])->execute();
        $queryBuilder->update('saml')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('spobject', $this->spobject)->execute();
    }

    /**
     * @param $postObject
     */
    public function storeToDatabase($postObject)
    {

        $this->myjson = json_encode($postObject);

        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::OIDC_TABLE);
        $uid = $queryBuilder->select('uid')->from(Constants::OIDC_TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
            ->execute()->fetchColumn(0);

        error_log("If Previous_IdP configured : ".$uid);

        if ($uid == null) {
            error_log("No Previous_IdP found : ".$uid);
            $affectedRows = $queryBuilder
                ->insert(Constants::OIDC_TABLE)
                ->values([
                    'uid' => $queryBuilder->createNamedParameter(1, PDO::PARAM_INT),
                    'app_name' => $postObject['app_name'],
                    'app_display_name' => $postObject['app_display_name'],
                    'redirect_url' => $postObject['redirect_url'],
                    'client_id' => $postObject['client_id'],
                    'client_secret' => $postObject['client_secret'],
                    'scope' => $postObject['scope'],
                    'auth_endpoint' => $postObject['auth_endpoint'],
                    'token_endpoint' => $postObject['token_endpoint'],
                    'user_info_endpoint' => $postObject['user_info_endpoint'],
                    'set_header_credentials' => $postObject['set_header_credentials'],
                    'set_body_credentials' => $postObject['set_body_credentials'],
                    'grant_type' => Constants::DEFAULT_GRANT_TYPE,
                    'oidc_object' => $this->myjson])
                ->execute();
            error_log("affected rows ".$affectedRows);
        }else {

            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::OIDC_TABLE);
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('app_name', $postObject['app_name'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('app_display_name', $postObject['app_display_name'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('client_id', $postObject['client_id'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('client_secret', $postObject['client_secret'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('auth_endpoint', $postObject['auth_endpoint'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('token_endpoint', $postObject['token_endpoint'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('user_info_endpoint', $postObject['user_info_endpoint'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
                ->set('scope', $postObject['scope'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('auth_endpoint', $postObject['auth_endpoint'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('set_header_credentials', $postObject['set_header_credentials'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('set_body_credentials', $postObject['set_body_credentials'])->execute();
            $queryBuilder->update(Constants::OIDC_TABLE)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('oidc_object', $this->myjson)->execute();
        }
    }
}
