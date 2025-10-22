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

    # reversed_char_string = reversed_string(provided_string)
    # palindrome = reversed_char_string == provided_string

    palindrome = provided_string.lower().replace(" ", "") == reversed_string(provided_string.lower().replace(" ", ""))

    data = {
        "id": hashed_string,
        "value": provided_string,
        "properties": {
            "length": len(provided_string_char_collection),
            "is_palindrome": palindrome,
            "unique_characters": len(set(provided_string_char_collection)),
            "word_count": len(provided_string.split()),
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
    is_palindrome: bool = Query(..., description="Whether the string is a palindrome"),
    min_length: int = Query(..., description="Minimum string length"),
    max_length: int = Query(..., description="Maximum string length"),
    word_count: int = Query(..., description="Exact word count"),
    contains_character: str = Query(..., min_length=1, description="Character that must appear in the string")
):
    if len(contains_character) > 1:
        raise BadRequestException("contains_character must be a single character.")

    search_char = contains_character.lower()
    filtered_strings = []

    try:
        for index_item in StringDB:
            props = index_item["properties"]

            if props["is_palindrome"] != is_palindrome:
                continue

            if not (min_length <= props["length"] <= max_length):
                continue

            if props["word_count"] != word_count:
                continue

            if search_char not in index_item["value"].lower():
                continue

            filtered_strings.append(index_item)

    except Exception as e:
        raise BadRequestException(f"Invalid query parameters: {str(e)}")

    if not filtered_strings:
        raise NotFoundException("No String matches this query in the system.")

    response_data = {
        "data": filtered_strings,
        "count": len(filtered_strings),
        "filters_applied": {
            "is_palindrome": is_palindrome,
            "min_length": min_length,
            "max_length": max_length,
            "word_count": word_count,
            "contains_character": contains_character
        }
    }

    return JSONResponse(content=response_data, status_code=200, media_type="application/json")


@app.delete("/strings/{string_value}")
async def delete_string(request: Request, string_value: str):
    provided_string = string_value
    data = None

    for item in StringDB:
        if item['value'] == provided_string:
            data = item
            break

    if data is None:
        raise NotFoundException("String does not exist in the system.")

    StringDB.remove(data)

    return Response(status_code=204)


@limiter.limit("8/minute")
@app.get("/strings/filter-by-natural-language")
async def filter_by_natural_language(
    request: Request,
    query: str = Query(..., description="A natural language filter query")
):
    query_lower = query.lower()
    parsed_filters = {}

    if "palindromic" in query_lower:
        parsed_filters["is_palindrome"] = True

    if "single word" in query_lower or "one word" in query_lower:
        parsed_filters["word_count"] = 1

    if "longer than" in query_lower:
        try:
            num = int(''.join([ch for ch in query_lower.split("longer than")[-1] if ch.isdigit()]))
            parsed_filters["min_length"] = num + 1
        except ValueError:
            raise BadRequestException("Unable to parse numeric value from query.")

    if "containing the letter" in query_lower:
        try:
            letter = query_lower.split("containing the letter")[-1].strip()[0]
            parsed_filters["contains_character"] = letter
        except Exception:
            raise BadRequestException("Unable to parse character from query.")

    if not parsed_filters:
        raise BadRequestException("Unable to parse natural language query.")

    # Apply filters
    filtered_strings = []
    for index_item in StringDB:
        props = index_item["properties"]

        if "is_palindrome" in parsed_filters and props["is_palindrome"] != parsed_filters["is_palindrome"]:
            continue

        if "word_count" in parsed_filters and props["word_count"] != parsed_filters["word_count"]:
            continue

        if "min_length" in parsed_filters and props["length"] < parsed_filters["min_length"]:
            continue

        if "contains_character" in parsed_filters and parsed_filters["contains_character"].lower() not in index_item["value"].lower():
            continue

        filtered_strings.append(index_item)

    if not filtered_strings:
        raise NotFoundException("No String matches this query in the system.")

    data = {
        "data": filtered_strings,
        "count": len(filtered_strings),
        "interpreted_query": {
            "original": query,
            "parsed_filters": parsed_filters
        }
    }
    return JSONResponse(content=data, status_code=200)

