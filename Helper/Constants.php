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

    //TABLE NAMES
    const CUSTOMER_TABLE = 'mo_customer';
    const OIDC_TABLE = 'mo_oidc';

    // COLUMNS IN CUSTOMER_TABLE
    const CUSTOMER_EMAIL = "cust_email";
    const CUSTOMER_KEY = "cust_key";
    const CUSTOMER_API_KEY = "cust_api_key";
    const CUSTOMER_TOKEN = "cust_token";
    const REG_STATUS = "cust_reg_status";

    //DATABASE COLUMN IN OIDC_TABLE


    //GRANT_TYPES CONSTANTS
    const AUTH_CODE_GRANT = "auth_code_grant";
    const IMPLICIT_GRANT = "implicit_grant";
    const PASSWORD_GRANT = "password_grant";
    const REFRESH_TOKEN_GRANT = "refresh_token_grant";
    const DEFAULT_GRANT_TYPE = self::AUTH_CODE_GRANT;

    const DEFAULT_CUSTOMER_KEY = "16555";
    const DEFAULT_API_KEY = "fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq";

    const AREA_OF_INTEREST = "TYPO3 OpenID Connect Client";


}