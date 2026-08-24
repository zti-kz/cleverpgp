class BioPGPError(Exception):
    """Base class for errors that are safe to show in the UI."""


class ValidationError(BioPGPError):
    pass


class ProfileExistsError(BioPGPError):
    pass


class ProfileNotFoundError(BioPGPError):
    pass


class AuthenticationError(BioPGPError):
    pass


class SessionLockedError(BioPGPError):
    pass


class InvalidEncryptedFileError(BioPGPError):
    pass


class OutputExistsError(BioPGPError):
    pass


class CryptographicIdentityError(BioPGPError):
    pass


class ContactExistsError(BioPGPError):
    pass


class ContainerError(BioPGPError):
    pass


class InvalidContainerError(ContainerError):
    pass


class ContainerEntryNotFoundError(ContainerError):
    pass


class ContainerEntryExistsError(ContainerError):
    pass


class ContainerNotDirectoryError(ContainerError):
    pass


class ContainerIsDirectoryError(ContainerError):
    pass


class ContainerDirectoryNotEmptyError(ContainerError):
    pass


class ContainerFullError(ContainerError):
    pass


class MountUnavailableError(ContainerError):
    pass


class BiometricError(BioPGPError):
    pass


class BiometricUnavailableError(BiometricError):
    pass


class BiometricNotEnrolledError(BiometricError):
    pass


class ModelIntegrityError(BiometricError):
    pass
