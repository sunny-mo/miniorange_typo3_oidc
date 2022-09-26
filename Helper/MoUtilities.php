<?php

// miniOrange Utilities for Typo 3

namespace Miniorange\Helper;

    use Exception;
    use PDO;
    use TYPO3\CMS\Core\Database\ConnectionPool;
    use TYPO3\CMS\Core\Messaging\FlashMessage;
    use TYPO3\CMS\Core\Messaging\FlashMessageQueue;
    use TYPO3\CMS\Core\Messaging\FlashMessageService;
    use TYPO3\CMS\Core\Messaging\Renderer\ListRenderer;
    use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
    use TYPO3\CMS\Core\Utility\GeneralUtility;
    use TYPO3\CMS\Core\Utility\PathUtility;

    //const SEP = DIRECTORY_SEPARATOR;

	class MoUtilities
    {
			/**
			 * Get resource director path
			 * rn string
			 */
			public static function getResourceDir()
			{
					$baseUrl = self::getBaseUrl();
                    global $sep;
                    $sep = substr(ExtensionManagementUtility::siteRelPath('miniorange_oidc'), -1);
                    $resFolder = ExtensionManagementUtility::siteRelPath('miniorange_oidc').'sso'.$sep.'resources'.$sep;
//                  error_log("Relative Resource folder : ".$resFolder);
                    return $resFolder;
			}

			public static function getExtensionAbsolutePath(){
				return ExtensionManagementUtility::extPath('miniorange_oidc');
			}

			public static function getExtensionRelativePath(){

                $extRelativePath= PathUtility::getAbsoluteWebPath(self::getExtensionAbsolutePath());
                error_log("AbsoluteWebPath : ".$extRelativePath);
				return $extRelativePath;
			}

			/**
			 * Get the Private Key File Path
			 * @return string
			 */
			public static function getPrivateKey()
			{
					return self::getResourceDir().DIRECTORY_SEPARATOR.Constants::SP_KEY;
			}

            /**
             *---------FETCH CUSTOMER DETAILS-------------------------
            */
			public static function fetch_cust($col)
			{
				$queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('customer');
				$variable = $queryBuilder->select($col)->from('customer')->where($queryBuilder->expr()->eq('id', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->execute()->fetchColumn(0);
				return $variable;
			}

            /**
            * --------- UPDATE CUSTOMER DETAILS --------------------------------
            */
			public static function update_cust($column, $value)
			{
				if(self::fetch_cust('id') == null)
				{
					self::insertValue();
				}
				$queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('customer');
				$queryBuilder->update('customer')->where($queryBuilder->expr()->eq('id', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set($column, $value)->execute();
			}

            /**
             *---------INSERT CUSTOMER DETAILS--------------
            */
			public static function insertValue()
			{
				$queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('customer');
				$affectedRows = $queryBuilder->insert('customer')->values([  'id' => '1' ])->execute();
			}

			public static function getAlternatePrivateKey(){
					return self::getResourceDir().DIRECTORY_SEPARATOR.Constants::SP_ALTERNATE_KEY;
			}

			/**
			 * Get the Public Key File Path
			 * @return string
			 */
			public static function getPublicKey()
			{
					return self::getResourceDir().DIRECTORY_SEPARATOR.Constants::SP_KEY;
			}

			/**
			 * Get Image Resource URL
			 */
			public static function getImageUrl($imgFileName)
			{
                $imageDir  = self::getResourceDir().SEP.'images'.SEP;
                error_log("resDir : ".$imageDir);
                $iconDir = self::getExtensionRelativePath().SEP.'Resources'.SEP.'Public'.SEP.'Icons'.SEP;
                error_log("iconDir : ".$iconDir);
                return $iconDir.$imgFileName;
			}

			/**
			 * Get the base url of the site.
			 * @return string
			 */
			public static function getBaseUrl()
			{
					$pageURL = 'http';

					if ((isset($_SERVER["HTTPS"])) && ($_SERVER["HTTPS"] == "on"))
							$pageURL .= "s";

					$pageURL .= "://";

					if ($_SERVER["SERVER_PORT"] != "80")
							$pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"];
					else
							$pageURL .= $_SERVER["SERVER_NAME"];

					return $pageURL;
			}

			/**
			 * The function returns the current page URL.
			 * @return string
			 */
			public static function currentPageUrl()
			{
					return self::getBaseUrl() . $_SERVER["REQUEST_URI"];
			}

			public static function check_certificate_format($certificate){
					if(!@openssl_x509_read($certificate)){
							throw new Exception("Certificate configured in the connector is in wrong format");
					}else{
						return 1;
					}
			}

			/**
			 * This function sanitizes the certificate
			 */
			public static function sanitize_certificate( $certificate ) {
					$certificate = trim($certificate);
					$certificate = preg_replace("/[\r\n]+/", "", $certificate);
					$certificate = str_replace( "-", "", $certificate );
					$certificate = str_replace( "BEGIN CERTIFICATE", "", $certificate );
					$certificate = str_replace( "END CERTIFICATE", "", $certificate );
					$certificate = str_replace( " ", "", $certificate );
					$certificate = chunk_split($certificate, 64, "\r\n");
					$certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . "-----END CERTIFICATE-----";
					return $certificate;
			}

			public static function desanitize_certificate( $certificate ) {
					$certificate = preg_replace("/[\r\n]+/", "", $certificate);
					//$certificate = str_replace( "-", "", $certificate );
					$certificate = str_replace( "-----BEGIN CERTIFICATE-----", "", $certificate );
					$certificate = str_replace( "-----END CERTIFICATE-----", "", $certificate );
					$certificate = str_replace( " ", "", $certificate );
					//$certificate = chunk_split($certificate, 64, "\r\n");
					//$certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . "-----END CERTIFICATE-----";
					return $certificate;
			}

			//Check if a value is null or empty
            public static function isEmptyOrNull( $t ) {
                if( ! isset( $t ) || empty( $t) ) {
                    return true;
                }
                return false;
            }

            //Update a value in Database
            // public static function updateColumn($column,$value,$table)
            // {
            //     $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($table);
            //     $affectedRows = $queryBuilder->insert($table)->values([ $column => $value ])->execute();
            // }

			public static function updateColumn($column,$value,$table)
			{
				$queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($table);
				$queryBuilder->update('mo_oidc')->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->set($column, $value)->execute();
			}

            //Fetch a value from Database
            public static function fetchFromDb($col, $table){
//                if( self::isEmptyOrNull($col) ){
                    $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($table);
                return $queryBuilder->select($col)->from($table)->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter(1, PDO::PARAM_INT)))->execute()->fetchColumn(0);
//                }else{
//                    error_log("Error invalid column or table name.");
//                }
			}

			public static function showErrorFlashMessage($message, $header="ERROR"){
				$message = GeneralUtility::makeInstance(FlashMessage::class,$message,$header,FlashMessage::ERROR);
				$out = GeneralUtility::makeInstance(ListRenderer ::class)->render([$message]);
				echo $out;
			}

			public static function showSuccessFlashMessage($message, $header="OK"){
				$message = GeneralUtility::makeInstance(FlashMessage::class, $message, $header, FlashMessage::OK);
				$out = GeneralUtility::makeInstance(ListRenderer ::class)->render([$message]);
				echo $out;
			}

			public static function clearFlashMessages(){
				$flashMessageService = GeneralUtility::makeInstance(FlashMessageService::class);
				$messageQueue  = $flashMessageService->getMessageQueueByIdentifier();
				$messageQueue->clear();
			}

    }