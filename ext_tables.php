<?php
defined('TYPO3_MODE') || die('Access denied.');

call_user_func(
    function()
    {

        \TYPO3\CMS\Extbase\Utility\ExtensionUtility::registerPlugin(
            'Miniorange.MiniorangeOidc',
            'Feoidc',
            'Feoidc'
        );

        \TYPO3\CMS\Extbase\Utility\ExtensionUtility::registerPlugin(
            'Miniorange.MiniorangeOidc',
            'Response',
            'Response'
        );

        \TYPO3\CMS\Extbase\Utility\ExtensionUtility::registerPlugin(
            'Miniorange.MiniorangeOidc',
            'Logout',
            'Logout'
        );

        if (TYPO3_MODE === 'BE') {
            \TYPO3\CMS\Extbase\Utility\ExtensionUtility::registerModule(
                'Miniorange.MiniorangeOidc',
                'tools', // Make module a submodule of 'tools'
                'bekey', // Submodule key
                '', // Position
                [
                    'Beoidc' => 'request',
                ],
                [
                    'access' => 'user,group',
                    'icon'   => 'EXT:miniorange_oidc/Resources/Public/Icons/miniorange.png',
                    'labels' => 'LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_bekey.xlf',
                ]
            );
        }

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addStaticFile('miniorange_oidc', 'Configuration/TypoScript', '');

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addLLrefForTCAdescr('tx_miniorangeoidc_domain_model_feoidc', 'EXT:miniorange_oidc/Resources/Private/Language/locallang_csh_tx_miniorangeoidc_domain_model_feoidc.xlf');
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::allowTableOnStandardPages('tx_miniorangeoidc_domain_model_feoidc');

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addLLrefForTCAdescr('tx_miniorangeoidc_domain_model_beoidc', 'EXT:miniorange_oidc/Resources/Private/Language/locallang_csh_tx_miniorangeoidc_domain_model_beoidc.xlf');
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::allowTableOnStandardPages('tx_miniorangeoidc_domain_model_beoidc');

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addLLrefForTCAdescr('tx_miniorangeoidc_domain_model_response', 'EXT:miniorange_oidc/Resources/Private/Language/locallang_csh_tx_miniorangeoidc_domain_model_response.xlf');
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::allowTableOnStandardPages('tx_miniorangeoidc_domain_model_response');

        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addLLrefForTCAdescr('tx_miniorangeoidc_domain_model_logout', 'EXT:miniorange_oidc/Resources/Private/Language/locallang_csh_tx_miniorangeoidc_domain_model_logout.xlf');
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::allowTableOnStandardPages('tx_miniorangeoidc_domain_model_logout');

    }
);
