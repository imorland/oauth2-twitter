<?php

namespace IanM\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class TwitterResourceOwner implements ResourceOwnerInterface
{
    /**
     * @var array
     */
    protected $response;

    /**
     * @param array $response
     */
    public function __construct(array $response)
    {
        $this->response = $response['data'] ?? [];
    }

    /**
     * {@inheritDoc}
     */
    public function getId()
    {
        return $this->response['id'];
    }

    public function getName()
    {
        return $this->response['name'];
    }

    public function getUsername()
    {
        return $this->response['username'];
    }

    public function getProfileImageUrl()
    {
        return $this->response['profile_image_url'];
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        return $this->response;
    }

    public function getResponseValue($key)
    {
        return $this->response[$key] ?? null;
    }
}
