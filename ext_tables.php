<?php

use TYPO3\CMS\Extbase\Utility\ExtensionUtility;

defined('TYPO3_MODE') || die('Access denied.');

call_user_func(
    function()
    {

        if(version_compare(TYPO3_version, '10.0.0', '>=')) {
            $extensionName = 'MiniorangeOidc';
            $cache_actions_beoidc = [ Miniorange\MiniorangeOidc\Controller\BeoidcController::class => 'request' ];
        } else {
            $extensionName = 'Miniorange.MiniorangeOidc';
            $cache_actions_beoidc = ['Beoidc' => 'request'];
        }

        ExtensionUtility::registerPlugin(
            $extensionName,
            'Feoidc',
            'feoidc'
        );

        ExtensionUtility::registerPlugin(
            $extensionName,
            'Response',
            'response'
        );

        if (TYPO3_MODE === 'BE') {
            ExtensionUtility::registerModule(
                $extensionName,
                'tools', // Make module a submodule of 'tools'
                'beoidc', // Submodule key
                '', // Position
                $cache_actions_beoidc,
                [
                    'access' => 'user,group',
                    'icon'   => 'EXT:miniorange_oidc/Resources/Public/Icons/miniorange.png',
                    'labels' => 'LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_beoidc.xlf',
                ]
            );
        }

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addStaticFile('miniorange_oidc', 'Configuration/TypoScript', 'Miniorange Oidc');

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addLLrefForTCAdescr('tx_miniorangeoidc_domain_model_feoidc', 'EXT:miniorange_oidc/Resources/Private/Language/locallang_csh_tx_miniorangeoidc_domain_model_feoidc.xlf');
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::allowTableOnStandardPages('tx_miniorangeoidc_domain_model_feoidc');

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addLLrefForTCAdescr('tx_miniorangeoidc_domain_model_beoidc', 'EXT:miniorange_oidc/Resources/Private/Language/locallang_csh_tx_miniorangeoidc_domain_model_beoidc.xlf');
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::allowTableOnStandardPages('tx_miniorangeoidc_domain_model_beoidc');

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addLLrefForTCAdescr('tx_miniorangeoidc_domain_model_response', 'EXT:miniorange_oidc/Resources/Private/Language/locallang_csh_tx_miniorangeoidc_domain_model_response.xlf');
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::allowTableOnStandardPages('tx_miniorangeoidc_domain_model_response');
    }
);

