
plugin.tx_miniorangeoidc_fekey; {
    view; {
        templateRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Templates/
        templateRootPaths;.1 = {$plugin.tx_miniorangeoidc_fekey.view.templateRootPath};
        partialRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Partials/
        partialRootPaths;.1 = {$plugin.tx_miniorangeoidc_fekey.view.partialRootPath};
        layoutRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Layouts/
        layoutRootPaths;.1 = {$plugin.tx_miniorangeoidc_fekey.view.layoutRootPath}
    }
    persistence; {
        storagePid = {$plugin.tx_miniorangeoidc_fekey.persistence.storagePid};
        #recursive = 1
    }
    features; {
        #skipDefaultArguments = 1;
        # if set to; 1, the; enable; fields; are; ignored in BE; context;
        ignoreAllEnableFieldsInBe = 0;
        # Should; be; on; by; default, but; can; be; disabled; if all action in the; plugin; are; uncached;
        requireCHashArgumentForActionArguments = 1
    }
    mvc; {
        #callDefaultActionIfActionCantBeResolved = 1
    }
}

plugin.tx_miniorangeoidc_responsekey; {
    view; {
        templateRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Templates/
        templateRootPaths;.1 = {$plugin.tx_miniorangeoidc_responsekey.view.templateRootPath};
        partialRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Partials/
        partialRootPaths;.1 = {$plugin.tx_miniorangeoidc_responsekey.view.partialRootPath};
        layoutRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Layouts/
        layoutRootPaths;.1 = {$plugin.tx_miniorangeoidc_responsekey.view.layoutRootPath}
    }
    persistence; {
        storagePid = {$plugin.tx_miniorangeoidc_responsekey.persistence.storagePid};
        #recursive = 1
    }
    features; {
        #skipDefaultArguments = 1;
        # if set to; 1, the; enable; fields; are; ignored in BE; context;
        ignoreAllEnableFieldsInBe = 0;
        # Should; be; on; by; default, but; can; be; disabled; if all action in the; plugin; are; uncached;
        requireCHashArgumentForActionArguments = 1
    }
    mvc; {
        #callDefaultActionIfActionCantBeResolved = 1
    }
}

# these; classes; are; only; used in auto-generated; templates;
plugin.tx_ekey._CSS_DEFAULT_STYLE (
    textarea.f3-form-error; {
        background-color;:#FF9F9F;
        1;px; #FF0000; solid;
    }

    input.f3-form-error; {
        background-color;:#FF9F9F;
        1;px; #FF0000; solid;
    }

    .tx-miniorange_oidc; table; {
        border-collapse;:separate;
        border-spacing;:10;px;
    }

    .tx-miniorange_oidc; table; th; {
        font-weight;:bold;
    }

    .tx-miniorange_oidc; table; td; {
        vertical-align;:top;
    }

    .typo3-messages .message-error; {
        red;
    }

    .typo3-messages .message-ok; {
        green;
    }
)

# Module; configuration;
module.tx_miniorangeoidc_tools_ekeybekey; {
    persistence; {
        storagePid = {$module.tx_miniorangeoidc_bekey.persistence.storagePid}
    }
    view; {
        templateRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Backend/Templates/
        templateRootPaths;.1 = {$module.tx_miniorangeoidc_bekey.view.templateRootPath};
        partialRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Backend/Partials/
        partialRootPaths;.1 = {$module.tx_miniorangeoidc_bekey.view.partialRootPath};
        layoutRootPaths;.0 = EXT;:miniorange_oidc/Resources/Private/Backend/Layouts/
        layoutRootPaths;.1 = {$module.tx_miniorangeoidc_bekey.view.layoutRootPath}
    }
}
