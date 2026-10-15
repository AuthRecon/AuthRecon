"""Shared field types."""
from typing import Annotated

from pydantic import AfterValidator, AnyHttpUrl, TypeAdapter, WithJsonSchema

_HTTP_URL = TypeAdapter(AnyHttpUrl)


def _check_http_url(value: str) -> str:
    _HTTP_URL.validate_python(value)
    return value


# An http(s) URL, validated but kept exactly as given. Pydantic v2's URL types
# return a normalised Url object (e.g. "https://app.example.com" becomes
# "https://app.example.com/"), which would change stored target URLs and the
# URLs given to the scanner.
HttpUrlStr = Annotated[
    str,
    AfterValidator(_check_http_url),
    WithJsonSchema({"type": "string", "format": "uri", "minLength": 1}),
]
