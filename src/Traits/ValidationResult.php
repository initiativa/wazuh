<?php

namespace GlpiPlugin\Wazuh\Traits;

readonly class ValidationResult {
    public function __construct(
        private mixed   $value = null,
        private ?string $error = null
    ) {}

    public static function ok(mixed $value): self {
        return new self($value);
    }

    public static function error(string $error): self {
        return new self(null, $error);
    }

    public function isValid(): bool {
        return $this->error === null;
    }

    public function getValue(): mixed {
        return $this->value;
    }

    public function getErrorMessage(): ?string {
        return $this->error;
    }
}