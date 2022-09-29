<?php
namespace Miniorange\MiniorangeOidc\Domain\Model;
/**
 * Beoidc
 */
class Beoidc extends TYPO3\CMS\Extbase\DomainObject\AbstractEntity
{
    public $idp_name = '';

    /**
     * @param $idp_name
     */
    public function __construct($idp_name)
    {
        $this->setIdpName($idp_name);
    }

    /**
     * @param $idp_name
     */
    public function setIdpName($idp_name)
    {
        $this->idp_name = $idp_name;
    }
}
