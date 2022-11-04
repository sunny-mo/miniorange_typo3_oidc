<?php

use TYPO3\CMS\Core\Imaging\IconProvider\BitmapIconProvider;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Utility\ExtensionUtility;

defined('TYPO3_MODE') || die('Access denied.');

call_user_func(
    function()
    {

        $pluginNameFeoidc = 'Feoidc';
         $pluginNameResponse = 'Response';

        if (version_compare(TYPO3_version, '10.0.0', '>=')) {
            $extensionName = 'MiniorangeOidc';
            $cache_actions_feoidc = [Miniorange\MiniorangeOidc\Controller\FeoidcController::class => 'request'];
            $non_cache_actions_feoidc = [Miniorange\MiniorangeOidc\Controller\FeoidcController::class => 'control'];
            $cache_actions_response = [Miniorange\MiniorangeOidc\Controller\ResponseController::class => 'response'];
            
        }else{
            $extensionName = 'Miniorange.MiniorangeOidc';
            $cache_actions_feoidc = [ 'Feoidc' => 'request' ];
            $non_cache_actions_feoidc = [ 'Feoidc' => 'control' ];
            $cache_actions_response = [ 'Response' => 'response' ];
        }
        ExtensionUtility::configurePlugin(
            $extensionName,
            $pluginNameFeoidc,
            $cache_actions_feoidc,
            // non-cacheable actions
            $non_cache_actions_feoidc
        );

        ExtensionUtility::configurePlugin(
            $extensionName,
            $pluginNameResponse,
            $cache_actions_response
        );
        
        // wizards
        ExtensionManagementUtility::addPageTSConfig(
            'mod {
            wizards.newContentElement.wizardItems.plugins {
                elements {
                    Feoidckey {
                        iconIdentifier = miniorange_oidc-plugin-feoidc
                        title = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_feoidc.name
                        description = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_feoidc.description
                        tt_content_defValues {
                            CType = list
                            list_type = feoidc
                        }
                    }
                    Responsekey {
                        iconIdentifier = miniorange_oidc-plugin-response
                        title = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_response.name
                        description = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_response.description
                        tt_content_defValues {
                            CType = list
                            list_type = response
                        }
                    }
                }
                show = *
            }
       }'
        );

        $iconRegistry = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(\TYPO3\CMS\Core\Imaging\IconRegistry::class);
        $iconRegistry->registerIcon(
            'miniorange_oidc-plugin-feoidc',
            \TYPO3\CMS\Core\Imaging\IconProvider\BitmapIconProvider::class,
            ['source' => 'EXT:miniorange_oidc/Resources/Public/Icons/miniorange.png']
        );
        $iconRegistry->registerIcon(
            'miniorange_oidc-plugin-response',
            \TYPO3\CMS\Core\Imaging\IconProvider\BitmapIconProvider::class,
            ['source' => 'EXT:miniorange_oidc/Resources/Public/Icons/miniorange.png']
        );
    }
);
