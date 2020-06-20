<?php
defined('TYPO3_MODE') || die('Access denied.');

call_user_func(
    function()
    {

        \TYPO3\CMS\Extbase\Utility\ExtensionUtility::configurePlugin(
            'Miniorange.Oidc',
            'Feoidc',
            [
                'Feoidc' => 'print'
            ],
            // non-cacheable actions
            [
                'Feoidc' => 'control'
            ]
        );

        \TYPO3\CMS\Extbase\Utility\ExtensionUtility::configurePlugin(
            'Miniorange.Oidc',
            'Response',
            [
                'Response' => 'check'
            ],
            // non-cacheable actions
            [
                'Feoidc' => '',
                'Beoidc' => '',
                'Response' => ''
            ]
        );
        
        // wizards
        \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addPageTSConfig(
            'mod {
            wizards.newContentElement.wizardItems.plugins {
                elements {
                    Feoidckey {
                        iconIdentifier = miniorange_oidc-plugin-feoidc
                        title = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_feoidc.name
                        description = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_feoidc.description
                        tt_content_defValues {
                            CType = list
                            list_type = Feoidc
                        }
                    }
                    Responsekey {
                        iconIdentifier = miniorange_oidc-plugin-response
                        title = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_response.name
                        description = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_response.description
                        tt_content_defValues {
                            CType = list
                            list_type = Response
                        }
                    }
                     Logoutkey {
                        iconIdentifier = miniorange_oidc-plugin-logout
                        title = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_logout.name
                        description = LLL:EXT:miniorange_oidc/Resources/Private/Language/locallang_db.xlf:tx_MiniorangeOidc_logout.description
                        tt_content_defValues {
                            CType = list
                            list_type = Logout
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
        $iconRegistry->registerIcon(
            'miniorange_oidc-plugin-logout',
            \TYPO3\CMS\Core\Imaging\IconProvider\BitmapIconProvider::class,
            ['source' => 'EXT:miniorange_oidc/Resources/Public/Icons/miniorange.png']
        );

    }
);
