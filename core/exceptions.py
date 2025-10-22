from fastapi import status

class AppException(Exception):
    """Base application exception with message and status code."""
    def __init__(self, message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class NotFoundException(AppException):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status.HTTP_404_NOT_FOUND)


class UnauthorizedException(AppException):
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)


class BadRequestException(AppException):
    def __init__(self, message: str = "Bad request"):
        super().__init__(message, status.HTTP_400_BAD_REQUEST)

class ConflictException(AppException):
    def __init__(self, message: str = "Bad request"):
        super().__init__(message, status.HTTP_409_CONFLICT)


class ExternalServiceException(AppException):
    def __init__(self, message: str = "External service error"):
        super().__init__(message, status.HTTP_502_BAD_GATEWAY)
