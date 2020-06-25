<?php

$EM_CONF[$_EXTKEY] = [
    'title' => 'Miniorange OIDC',
    'description' => 'Miniorange OpenID Connect (OIDC) Client plugin allows Single Sign On (SSO) with any OpenID Connect provider that conforms to the OpenID Connect 1.0 standard. You can SSO to your WordPress site with any OAuth 2.0 or OpenID Connect 1.0 provider using this plugin.',
    'category' => 'plugin',
    'author' => 'Miniorange',
    'author_email' => 'info@xecurify.com',
    'state' => 'alpha',
    'uploadfolder' => 0,
    'createDirs' => '',
    'clearCacheOnLoad' => 0,
    'version' => '0.1',
    'constraints' => [
        'depends' => [
            'typo3' => '8.7.0-9.6.0',
        ],
        'conflicts' => [],
        'suggests' => [],
    ],
		'autoload' => [
				'psr-4' => [
						'Miniorange\\MiniorangeOidc\\' => 'Classes',
						'Miniorange\\Helper\\' => 'Helper',
				]
		],

];