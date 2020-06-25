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
    * @var Miniorange\MiniorangeOidc\Domain\Repository\BeoidcRepository
    * @inject
    */
    public $beoidcRepository = null;

    private $myjson = null;

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

        if(isset($_POST['option'])){
            if(MoUtilities::isEmptyOrNull($_POST['app_type'])){
                $_POST['app_type'] = Constants::TYPE_OPENID_CONNECT;
            }
        }

//------------ OPENID CONNECT SETTINGS---------------
        if(isset($_POST['option']) and $_POST['option']=="oidc_settings"){
            error_log("Received OIDC Settings: " );
            if(MoUtilities::isEmptyOrNull($_POST['set_body_credentials'])){
                $_POST['set_body_credentials'] = 'false';
            }
            if(MoUtilities::isEmptyOrNull($_POST['set_header_credentials'])){
                $_POST['set_header_credentials'] = 'false';
            }
            $this->storeToDatabase($_POST);
        }

//------------ HANDLING SUPPORT QUERY---------------
        if ( isset( $_POST['option'] ) and $_POST['option'] == "mo_saml_contact_us_query_option" ) {
            error_log('Received support query.  ');
            $this->support();
        }

//------------ VERIFY CUSTOMER---------------
        if ( isset( $_POST['option'] ) and $_POST['option'] == "mo_verify_customer" ) {
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

//------------ ATTRIBUTE MAPPING---------------
        if (isset( $_POST['option'] ) and $_POST['option'] == "attribute_mapping"){

            $username = $_POST['oidc_am_username'];

            if(!MoUtilities::isEmptyOrNull($username))
            {
                if($this->fetchFromOidc('uid') == null){
                    MoUtilities::showErrorFlashMessage('Please configure OpenIDConnect client first.');
                }else{
//                    $tempAmObj = json_encode($_POST);
                    $this->updateOidc(Constants::OIDC_ATTRIBUTE_USERNAME,$username);
//                    $this->updateOidc(Constants::OIDC_ATTRIBUTE_OBJECT,$tempAmObj);
                    MoUtilities::showSuccessFlashMessage('Attribute Mapping saved successfully.');
                }
            }else{
                MoUtilities::showErrorFlashMessage('Please provide valid input.');
            }
        }

//------------ CHANGING TABS---------------
        if ($_POST['option'] == 'mo_verify_customer')
        {
            $this->tab = "Account";
        }
        elseif ($_POST['option'] == 'oidc_settings')
        {
            $this->tab = "OIDC_Settings";
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
        $this->view->assign('conf', json_decode($this->fetchFromOidc(Constants::OIDC_OIDC_OBJECT), true));
        $this->view->assign('conf_am', json_decode($this->fetchFromOidc(Constants::OIDC_ATTR_LIST_OBJECT), true));
        $this->view->assign('am_username', $this->fetchFromOidc(Constants::OIDC_ATTRIBUTE_USERNAME));
//------------ LOADING VARIABLES TO BE USED IN VIEW---------------
        if($this->fetchFromCustomer(Constants::CUSTOMER_REG_STATUS) == 'logged'){
            $this->view->assign('status','logged');
            $this->view->assign('log', '');
            $this->view->assign('nolog', 'display:none');
            $this->view->assign('email',$this->fetchFromCustomer(Constants::CUSTOMER_EMAIL));
            $this->view->assign('key',$this->fetchFromCustomer(Constants::CUSTOMER_KEY));
            $this->view->assign('token',$this->fetchFromCustomer(Constants::CUSTOMER_TOKEN));
            $this->view->assign('api_key',$this->fetchFromCustomer(Constants::CUSTOMER_API_KEY));
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
        $this->updateCustomer(Constants::CUSTOMER_KEY,'');
        $this->updateCustomer(Constants::CUSTOMER_EMAIL,'');
        $this->updateCustomer(Constants::CUSTOMER_TOKEN,'');
        $this->updateCustomer(Constants::CUSTOMER_API_KEY, '');
        $this->updateCustomer(Constants::CUSTOMER_REG_STATUS,'');

    }

//    VALIDATE CERTIFICATE
//    public function validate_cert($saml_x509_certificate)
//    {
//        error_log("saml_certificate : ".print_r($saml_x509_certificate,true));
//
//        $certificate = openssl_x509_parse ( $saml_x509_certificate);
//
//        error_log("parsed certificate : ".print_r($certificate,true));
//
//        foreach( $certificate as $key => $value ) {
//            if ( empty( $value ) ) {
//                unset( $saml_x509_certificate[ $key ] );
//                return 0;
//            } else {
//                $saml_x509_certificate[ $key ] = $this->sanitize_certificate( $value );
//                if ( ! @openssl_x509_read( $saml_x509_certificate[ $key ] ) ) {
//                    return 0;
//                }
//            }
//        }
//
//        if ( empty( $saml_x509_certificate ) ) {
//            return 0;
//        }
//
//        return 1;
//    }

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
        $this->updateCustomer(Constants::CUSTOMER_EMAIL, $email);
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
        $this->updateCustomer(Constants::CUSTOMER_KEY,$content['id']);
        $this->updateCustomer(Constants::CUSTOMER_API_KEY,$content['apiKey']);
        $this->updateCustomer(Constants::CUSTOMER_TOKEN,$content['token']);
        $this->updateCustomer(Constants::CUSTOMER_REG_STATUS, 'logged');
        $this->updateCustomer(Constants::CUSTOMER_EMAIL,$email);
    }

// FETCH CUSTOMER
    public function fetchFromCustomer($col)
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_CUSTOMER);
        $variable = $queryBuilder->select($col)->from(Constants::TABLE_CUSTOMER)->where($queryBuilder->expr()->eq('id', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->execute()->fetchColumn(0);
        return $variable;
    }

// ---- UPDATE CUSTOMER Details
    public function updateCustomer($column, $value)
    {
        if($this->fetchFromCustomer('id') == null)
        {
            $this->insertCustomerRow();
        }
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_CUSTOMER);
        $queryBuilder->update(Constants::TABLE_CUSTOMER)->where($queryBuilder->expr()->eq('id', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set($column, $value)->execute();
    }

    // FETCH OIDC VALUES
    public function fetchFromOidc($col){
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $variable = $queryBuilder->select($col)->from(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->execute()->fetchColumn(0);
        return $variable;
    }

// ---- UPDATE OIDC Settings
    public function updateOidc($column, $value)
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set($column, $value)->execute();
    }

    public function insertCustomerRow()
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_CUSTOMER);
        $affectedRows = $queryBuilder->insert(Constants::TABLE_CUSTOMER)->values([  'id' => '1' ])->execute();
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

    }

    /**
     * @param $postObject
     */
    public function storeToDatabase($postObject)
    {

        $this->myjson = json_encode($postObject);
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $uid = $queryBuilder->select('uid')->from(Constants::TABLE_OIDC)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
            ->execute()->fetchColumn(0);

        error_log("If Previous_IdP configured : ".$uid);

        if ($uid == null) {
            error_log("No Previous_IdP found : ".$uid);
            $affectedRows = $queryBuilder
                ->insert(Constants::TABLE_OIDC)
                ->values([
                    'uid' => $queryBuilder->createNamedParameter(1, PDO::PARAM_INT),
                    Constants::OIDC_APP_TYPE => $postObject['app_type'],
                    Constants::OIDC_APP_NAME => $postObject['app_name'],
                    Constants::OIDC_REDIRECT_URL => $postObject['redirect_url'],
                    Constants::OIDC_CLIENT_ID => $postObject['client_id'],
                    Constants::OIDC_CLIENT_SECRET => $postObject['client_secret'],
                    Constants::OIDC_SCOPE => $postObject['scope'],
                    Constants::OIDC_AUTH_URL => $postObject['auth_endpoint'],
                    Constants::OIDC_TOKEN_URL => $postObject['token_endpoint'],
                    Constants::OIDC_USER_INFO_URL => $postObject['user_info_endpoint'],
                    Constants::OIDC_SET_HEADER_CREDS => $postObject['set_header_credentials'],
                    Constants::OIDC_SET_BODY_CREDS => $postObject['set_body_credentials'],
                    Constants::OIDC_GRANT_TYPE => Constants::DEFAULT_GRANT_TYPE,
                    Constants::OIDC_OIDC_OBJECT => $this->myjson])
                ->execute();
            error_log("affected rows ".$affectedRows);
            MoUtilities::showSuccessFlashMessage('Open ID Settings are saved successfully');
        }else {

            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_APP_TYPE, $postObject['app_type'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_APP_NAME, $postObject['app_name'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_REDIRECT_URL, $postObject['redirect_url'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_CLIENT_ID, $postObject['client_id'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_CLIENT_SECRET, $postObject['client_secret'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_AUTH_URL, $postObject['auth_endpoint'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_TOKEN_URL, $postObject['token_endpoint'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_USER_INFO_URL, $postObject['user_info_endpoint'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_SCOPE, $postObject['scope'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_SET_HEADER_CREDS, $postObject['set_header_credentials'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_SET_BODY_CREDS, $postObject['set_body_credentials'])->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_GRANT_TYPE, Constants::DEFAULT_GRANT_TYPE)->execute();
            $queryBuilder->update(Constants::TABLE_OIDC)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set(Constants::OIDC_OIDC_OBJECT, $this->myjson)->execute();

            MoUtilities::showSuccessFlashMessage('Open ID Settings are updated successfully');
        }
    }
}
