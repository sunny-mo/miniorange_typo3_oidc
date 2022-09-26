<?php

namespace Miniorange\MiniorangeOidc\Controller;

use Exception;

use Miniorange\MiniorangeOidc\Domain\Model\Beoidc;
use Miniorange\Helper\MoUtilities;
use Miniorange\Helper\CustomerMo;
use Miniorange\Helper\Constants;
use Miniorange\Helper\Actions\TestResultActions;

use PDO;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Database\ConnectionPool;
use \TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Tstemplate\Controller\TypoScriptTemplateModuleController;
use TYPO3\CMS\Extbase\Object\ObjectManager;

use Miniorange\Helper\Utilities;
/**
 *BeoidcController
 */
class BeoidcController extends ActionController
{

    protected $tab = "";

    /**
     * @throws Exception
     */
    public function requestAction()
    {
        error_log("BeoidcController.php : In requestAction");
        $util=new Utilities();
        $baseurl= $util->currentPageUrl();
        $_SESSION['base_url']=$baseurl;

        if(isset($_POST['option'])){
            if(empty($_POST['app_type'])){
                $_POST['app_type'] = Constants::TYPE_OPENID_CONNECT;
            }
        }

//------------ OPENID CONNECT SETTINGS---------------
        if(isset($_POST['option']) and $_POST['option']=="oidc_settings"){
            if(empty($_POST['set_body_credentials'])){
                $_POST['set_body_credentials'] = 'false';
            }
            if(empty($_POST['set_header_credentials'])){
                $_POST['set_header_credentials'] = 'false';
            }
            $this->defaultSettings($_POST);
            $this->storeToDatabase($_POST);
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
                    $this->updateOidc(Constants::COLUMN_GROUP_DEFAULT,$_POST['defaultUserGroup']);
//                    $this->updateOidc(Constants::OIDC_ATTRIBUTE_OBJECT,$tempAmObj);
                    MoUtilities::showSuccessFlashMessage('Attribute Mapping saved successfully.');
                }
            }else{
                MoUtilities::showErrorFlashMessage('Please provide valid input.');
            }
        }

//------------ CHANGING TABS---------------
        if(!empty($_POST['option']))
        {
           if ($_POST['option'] == 'oidc_settings' || $_POST['option'] == '')
            {
                $this->tab = "OIDC_Settings";
            }
            elseif ($_POST['option'] == 'attribute_mapping')
            {
                $this->tab = "Attribute_Mapping";
            }
        }

        $this->objectManager = GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');
        $allUserGroups= $this->objectManager->get('TYPO3\\CMS\\Extbase\\Domain\\Repository\\FrontendUserGroupRepository')->findAll();
        //echo (print_r($allUserGroups,true));exit;
        $allUserGroups->getQuery()->getQuerySettings()->setRespectStoragePage(false);
        $this->view->assign('allUserGroups', $allUserGroups);
        $this->view->assign('defaultGroup',Utilities::fetchFromTable(Constants::COLUMN_GROUP_DEFAULT,Constants::TABLE_OIDC));

//------------ LOADING SAVED SETTINGS OBJECTS TO BE USED IN VIEW---------------
        $this->view->assign('conf', json_decode($this->fetchFromOidc('oidc_object'), true));
        $this->view->assign('conf_am', json_decode($this->fetchFromOidc(Constants::OIDC_ATTR_LIST_OBJECT), true));
        $this->view->assign('am_username', $this->fetchFromOidc(Constants::OIDC_ATTRIBUTE_USERNAME));

        $this->view->assign('tab', $this->tab);
GeneralUtility::makeInstance(\TYPO3\CMS\Core\Cache\CacheManager::class)->flushCaches();
    }

    public function save($column,$value,$table)
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($table);
        $affectedRows = $queryBuilder->insert($table)->values([ $column => $value, ])->execute();
    }

    public function mo_is_curl_installed() {
        if ( in_array( 'curl', get_loaded_extensions() ) ) {
            return 1;
        } else {
            return 0;
        }
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
        error_log("In BeoidcController : updateCustomer()");
        if($this->fetchFromCustomer('id') == null)
        {
            $this->insertCustomerRow();
        }
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_CUSTOMER);
        $queryBuilder->update(Constants::TABLE_CUSTOMER)->where($queryBuilder->expr()->eq('id', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set($column, $value)->execute();
    }

    // FETCH OIDC VALUES
    public function fetchFromOidc($col){
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('mo_oidc');
        $variable = $queryBuilder->select($col)->from('mo_oidc')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->execute()->fetchColumn(0);
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

        error_log("In BeoidcController : defaultSettings: ");
        $this->oidc_object = json_encode($postArray);
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $uid=$queryBuilder->select('uid')->from(Constants::TABLE_OIDC)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
            ->execute()->fetchColumn(0);
        if($uid== null)
        {
            $affectedRows = $queryBuilder
            ->insert(Constants::TABLE_OIDC)
            ->values([
                'uid' => $queryBuilder->createNamedParameter(1, PDO::PARAM_INT),
                'feoidc' => $this->oidc_object,
                'response' => $this->oidc_object,
                'oidc_object' => $this->oidc_object])
            ->execute();
        }
        else{
            $queryBuilder->update('mo_oidc')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('feoidc',$this->oidc_object)->execute();
            $queryBuilder->update('mo_oidc')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('response',$this->oidc_object)->execute();
            $queryBuilder->update('mo_oidc')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set('oidc_object', $this->oidc_object)->execute();
    }
    }

    /**
     * @param $postObject
     */
    public function storeToDatabase($postObject)
    {
        
        error_log("In BeoidcController : stroreToDatabase");
        $this->myjson = json_encode($postObject);
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(Constants::TABLE_OIDC);
        $uid = $queryBuilder->select('uid')->from(Constants::TABLE_OIDC)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))
            ->execute()->fetchColumn(0);

        if ($uid == null) {
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
