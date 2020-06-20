<?php

namespace MiniOrange\Helper;

class Constants
{

    //images
    const IMAGE_RIGHT 		= 'right.png';
    const IMAGE_WRONG 		= 'wrong.png';

    const HOSTNAME        = "https://login.xecurify.com";
    const HASH            = 'aec500ad83a2aaaa7d676c56d8015509d439d56e0e1726b847197f7f089dd8ed';
    const APPLICATION_NAME= 'typo3_oidc_client';

    // DATABASE COLUMNS IN CUSTOMER TABLE
    const CUSTOMER_EMAIL = "cust_email";
    const CUSTOMER_KEY = "cust_key";
    const CUSTOMER_API_KEY = "cust_api_key";
    const CUSTOMER_TOKEN = "cust_token";
    const REG_STATUS = "cust_reg_status";

    const DEFAULT_CUSTOMER_KEY = "16555";
    const DEFAULT_API_KEY = "fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq";

    const AREA_OF_INTEREST = "TYPO3 OpenID Connect Client";

}