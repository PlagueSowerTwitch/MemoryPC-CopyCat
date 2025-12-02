<?php

namespace App\Entity;

use App\Repository\CartRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use App\Entity\User;

#[ORM\Entity(repositoryClass: CartRepository::class)]
class Cart
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToMany(targetEntity: Product::class, inversedBy: 'carts')]
    private Collection $HasProduct;

    #[ORM\OneToOne(inversedBy: 'cart', cascade: ['persist', 'remove'])]
    #[ORM\JoinColumn(name: 'user_cart_id', referencedColumnName: 'id', onDelete: 'CASCADE')]
    private ?User $user_cart = null;

    public function __construct()
    {
        $this->HasProduct = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * @return Collection<int, Product>
     */
    public function getHasProduct(): Collection
    {
        return $this->HasProduct;
    }

    public function addHasProduct(Product $hasProduct): static
    {
        if (!$this->HasProduct->contains($hasProduct)) {
            $this->HasProduct->add($hasProduct);
        }

        return $this;
    }

    public function removeHasProduct(Product $hasProduct): static
    {
        $this->HasProduct->removeElement($hasProduct);
        return $this;
    }

    public function getUserCart(): ?User
    {
        return $this->user_cart;
    }

    public function setUserCart(?User $user_cart): static
    {
        $this->user_cart = $user_cart;
        return $this;
    }
}
