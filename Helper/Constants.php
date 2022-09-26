<?php

namespace Miniorange\Helper;

class Constants
{

    //images
    const IMAGE_RIGHT 		= 'right.png';
    const IMAGE_WRONG 		= 'wrong.png';

    const HOSTNAME        = "https://login.xecurify.com";
    const HASH            = 'aec500ad83a2aaaa7d676c56d8015509d439d56e0e1726b847197f7f089dd8ed';
    const APPLICATION_NAME= 'typo3_oidc_client';

    const TYPE_OPENID_CONNECT = 'OpenID Connect';
    const TYPE_OAUTH = 'OAuth';

    //TABLE NAMES
    const TABLE_CUSTOMER = 'mo_customer';
    const TABLE_OIDC = 'mo_oidc';
    const TABLE_FE_USERS = 'fe_users';

    //DATABASE COLUMN IN OIDC_TABLE
    const OIDC_APP_TYPE  = 'app_type';
    const OIDC_APP_NAME = 'app_name';// varchar (100) DEFAULT '' NOT NULL ,
    const OIDC_REDIRECT_URL = 'redirect_url'; //varchar (100) DEFAULT '' NOT NULL,
    const OIDC_CLIENT_ID = 'client_id'; //varchar (100) DEFAULT '' NOT NULL,
    const OIDC_CLIENT_SECRET = 'client_secret'; //varchar (1500) DEFAULT '',
    const OIDC_SCOPE = 'scope'; //varchar (100) DEFAULT '' ,
    const OIDC_AUTH_URL = 'auth_endpoint';// varchar (100) DEFAULT '' NOT NULL,
    const OIDC_TOKEN_URL = 'token_endpoint' ;//varchar (100) DEFAULT '' NOT NULL,
    const OIDC_USER_INFO_URL = 'user_info_endpoint';// varchar (100) DEFAULT '' NOT NULL,
    const OIDC_SET_HEADER_CREDS = 'set_header_credentials';// varchar (100) DEFAULT '' ,
    const OIDC_SET_BODY_CREDS = 'set_body_credentials' ;//varchar (100) DEFAULT '',
    const OIDC_GRANT_TYPE = 'grant_type';// varchar (100) DEFAULT '',
    const OIDC_ATTRIBUTE_USERNAME = 'oidc_am_username';//  varchar (100) DEFAULT '' ,
    const COLUMN_PLUGIN_RESPONSE_URL = 'response';
    const COLUMN_PLUGIN_FEOIDC_URL = 'feoidc';
    const COLUMN_GROUP_DEFAULT = 'defaultGroup';
//    const OIDC_ATTRIBUTE_EMAIL =   'oidc_am_email';// varchar (100) DEFAULT '' ,
//    const OIDC_ATTRIBUTE_FNAME =   'oidc_am_fname';// varchar (100) DEFAULT '' ,
//    const OIDC_ATTRIBUTE_LNAME =   'oidc_am_lname';// varchar (100) DEFAULT '' ,
//    const OIDC_ATTRIBUTE_GROUP =   'oidc_am_group';// varchar (100) DEFAULT '' ,
//    const OIDC_ATTRIBUTES_CUSTOM =   'custom_attrs';// varchar (1000) DEFAULT '',
    const OIDC_OIDC_OBJECT =   'oidc_object';// text DEFAULT '',
    const OIDC_ATTR_LIST_OBJECT =  'am_object';// text DEFAULT '',
    const OIDC_COUNT_USER = 'countuser';
    
    //GRANT_TYPES CONSTANTS
    const AUTH_CODE_GRANT = "authorization code";
    const IMPLICIT_GRANT = "implicit grant";
    const PASSWORD_GRANT = "password grant";
    const REFRESH_TOKEN_GRANT = "refresh token grant";
    const DEFAULT_GRANT_TYPE = self::AUTH_CODE_GRANT;

    const AREA_OF_INTEREST = "TYPO3 OpenID Connect Client";


}