from wsgiref.validate import assert_

from fastapi import FastAPI, Request, Response, Depends, Query
from datetime import datetime, timezone
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from core.error_handlers import register_error_handlers, conditional_validation_handler
from fastapi.exceptions import RequestValidationError
from services.http_client import safe_http_request
from core.exceptions import NotFoundException, BadRequestException, ConflictException
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from functools import lru_cache
from typing_extensions import Annotated
from core import config
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from typing import Dict, List, Any
import hashlib


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("App starting up...")
    await startup_event()
    yield
    # Shutdown
    print("App shutting down...")


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(lifespan=lifespan, title="My Profile App")
register_error_handlers(app)

# Register exception handlers
app.add_exception_handler(RateLimitExceeded, lambda request, exc: JSONResponse(
    status_code=429,
    content={"success": False, "error": "Too many requests, please slow down."},
))
app.add_exception_handler(RequestValidationError, conditional_validation_handler)


@lru_cache
def get_settings():
    return config.Settings()


# Initialize the limiter
async def startup_event():
    app.state.limiter = limiter


origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class StringProperty(BaseModel):
    length: int
    is_palindrome: bool = False
    unique_characters: int
    word_count: int
    sha256_hash: str
    character_frequency_map: Dict[str, int]


class DBItems(BaseModel):
    id: str
    value: str
    properties: StringProperty
    created_at: str


class Value(BaseModel):
    value: str = Field(..., min_length=1, description="A non-empty string value")


StringDB: List[DBItems] = []


def get_string_hash(string: str):
    encoded_value = string.encode("utf-8")
    hashed_value = hashlib.sha256(encoded_value).hexdigest()
    return hashed_value


@app.get("/")
async def home():
    return JSONResponse(content={
        "success": True,
        "message": {
            "title": "String Analyzer",
            "about": "This is a RESTful API service that analyzes strings and stores their computed properties."
        }
    }, status_code=200, media_type="application/json")


@app.get("/health")
async def health_check():
    return JSONResponse(content={
        "success": True,
        "message": "Ok"
    }, status_code=200, media_type="application/json")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


def reversed_string(string: str):
    provided_string_char_collection: list[str] = []
    for char in string:
        provided_string_char_collection.append(char)

    provided_string_char_collection.reverse()
    rev_string = "".join(provided_string_char_collection)
    return rev_string


@limiter.limit("8/minute")
@app.post("/strings")
async def analyze_string(request: Request, body: Value):
    provided_string = body.value

    for string in range(len(StringDB)):
        index_item = StringDB[string]
        if index_item['value'] == provided_string:
            raise ConflictException("String already exists in the system")

    hashed_string = get_string_hash(provided_string)
    no_space_string = provided_string.replace(" ", "")
    provided_string_char_collection: list[Any] = []
    for char in no_space_string:
        provided_string_char_collection.append(char)

    char_freq: dict[str, int] = {}
    for letter in provided_string_char_collection:
        duplicate_count = provided_string_char_collection.count(letter)
        char_freq[letter] = duplicate_count

    unique_char = 0
    for char in provided_string_char_collection:
        if provided_string_char_collection.count(char) == 1:
            unique_char += 1

    reversed_char_string = reversed_string(provided_string)
    palindrome = reversed_char_string == provided_string

    data = {
        "id": hashed_string,
        "value": provided_string,
        "properties": {
            "length": len(provided_string_char_collection),
            "is_palindrome": palindrome,
            "unique_characters": unique_char,
            "word_count": len(provided_string.split(" ")),
            "sha256_hash": hashed_string,
            "character_frequency_map": char_freq,
        },
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    StringDB.append(data)
    return JSONResponse(content=data, status_code=201, media_type="application/json")


@limiter.limit("8/minute")
@app.get("/all")
async def get_all_string(request: Request):
    data = StringDB

    if len(data) == 0:
        raise NotFoundException("There are no strings in the system.")

    return JSONResponse(content=data, status_code=200, media_type="application/json")


@limiter.limit("8/minute")
@app.get("/strings/{string_value}")
async def fetch_string(request: Request, string_value: str):
    provided_string = string_value
    data = None
    is_exist = 0

    for string in range(len(StringDB)):
        index_item = StringDB[string]
        if index_item['value'] == provided_string:
            is_exist = 1
            data = StringDB[string]
            break

    if is_exist == 0:
        raise NotFoundException("String does not exist in the system.")

    return JSONResponse(content=data, status_code=200, media_type="application/json")


@limiter.limit("8/minute")
@app.get("/strings")
async def filter_string(
    request: Request,
    is_palindrome: bool = Query(..., description="is palindrome cannot be empty"),
    min_length: int = Query(..., description="min length cannot be empty"),
    max_length: int = Query(..., description="max length cannot be empty"),
    word_count: int = Query(..., description="word count cannot be empty"),
    contains_character: str = Query(..., description="contains character cannot be empty"),
):
    try:
        palindrome = str(is_palindrome).lower() in ["true", "1", "yes"]
        search_char = contains_character.lower()
        filtered_strings = []

        for item in StringDB:
            props = item["properties"]
            if (
                props["is_palindrome"] == palindrome
                and min_length <= props["length"] <= max_length
                and props["word_count"] == word_count
                and search_char in item["value"].lower()
            ):
                filtered_strings.append(item)

        data = {
            "data": filtered_strings,
            "count": len(filtered_strings),
            "filters_applied": {
                "is_palindrome": palindrome,
                "min_length": min_length,
                "max_length": max_length,
                "word_count": word_count,
                "contains_character": contains_character
            }
        }

        return JSONResponse(content=data, status_code=200, media_type="application/json")

    except Exception:
        raise BadRequestException("Invalid query parameter values or types")



@app.delete("/strings/{string_value}")
async def delete_string(request: Request, string_value: str):
    provided_string = string_value
    data = None

    # Find the matching string
    for item in StringDB:
        if item['value'] == provided_string:
            data = item
            break

    # If not found, raise a clean custom error
    if data is None:
        raise NotFoundException("String does not exist in the system.")

    # Remove it safely
    StringDB.remove(data)

    # Return proper HTTP 204 (no body)
    return Response(status_code=204)


@limiter.limit("8/minute")
@app.get("/string/filter-by-natural-language")
async def filter_by_natural_language(request: Request,
                                     query: str = Query(..., description="Your search term")
                                     ):
    query_str = query
    natural_language = query_str.replace("%20", " ")

    nl = natural_language.lower()
    parsed = {}
    if "single word" in nl or "single-word" in nl:
        parsed["word_count"] = 1
    if "palindrom" in nl:
        parsed["is_palindrome"] = True

    filtered_strings = []
    for string in range(len(StringDB)):
        index_item = StringDB[string]
        if index_item['properties']['is_palindrome']:
            if index_item['properties']['word_count'] == 1:
                index_value = index_item['value']
                filtered_strings.append(index_value)

    if len(filtered_strings) == 0:
        raise NotFoundException("No String matches this queries in the system.")

    data = {
        "data": filtered_strings,
        "count": len(filtered_strings),
        "interpreted_query": {
            "original": natural_language,
            "parsed_filters": parsed
        }
    }
    return JSONResponse(content=data, status_code=200, media_type="application/json")
