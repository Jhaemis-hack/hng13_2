import re
from collections import Counter
import hashlib
from datetime import datetime, timezone
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
from typing import Dict, List, Any, Optional
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



def get_string_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def normalize_for_palindrome(s: str) -> str:
    # remove non-alphanumeric and lowercase
    return re.sub(r'[^0-9a-zA-Z]', '', s).lower()

def compute_string_properties(value: str) -> dict:
    length = len(value)

    word_count = len([w for w in value.split() if w])

    no_space = value.replace(" ", "")

    char_freq = dict(Counter(no_space))

    unique_characters = len(set(no_space))

    normalized = normalize_for_palindrome(value)
    is_palindrome = normalized == normalized[::-1] and len(normalized) > 0

    sha256_hash = get_string_hash(value)

    return {
        "length": length,
        "is_palindrome": is_palindrome,
        "unique_characters": unique_characters,
        "word_count": word_count,
        "sha256_hash": sha256_hash,
        "character_frequency_map": char_freq
    }


@limiter.limit("8/minute")
@app.post("/strings")
async def analyze_string(request: Request, body: Value):
    provided_string = body.value

    # Duplicate check: exact match (case-sensitive). Change to .lower() for case-insensitive uniqueness if desired.
    for item in StringDB:
        if item["value"] == provided_string:
            raise ConflictException("String already exists in the system")

    props = compute_string_properties(provided_string)
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    data = {
        "id": props["sha256_hash"],
        "value": provided_string,
        "properties": props,
        "created_at": now_iso
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


from fastapi import Query

@limiter.limit("8/minute")
@app.get("/strings")
async def filter_strings(request: Request,
    is_palindrome: Optional[bool] = Query(None, description="Optional palindrome filter"),
    min_length: Optional[int] = Query(None, description="Minimum string length"),
    max_length: Optional[int] = Query(None, description="Maximum string length"),
    word_count: Optional[int] = Query(None, description="Exact word count"),
    contains_character: Optional[str] = Query(None, description="Character to search for")
):
    if not any([is_palindrome, min_length, max_length, word_count, contains_character]):
        raise BadRequestException("At least one filter must be provided.")

    filtered = []

    for item in StringDB:
        value = item.get("value", "")
        props = item.get("properties", {})
        length = len(value)
        wc = len(value.split())
        palindrome_check = value.lower() == value.lower()[::-1]

        match = True

        if is_palindrome is not None and palindrome_check != is_palindrome:
            match = False

        if min_length is not None and length < min_length:
            match = False

        if max_length is not None and length > max_length:
            match = False

        if word_count is not None and wc != word_count:
            match = False

        if contains_character is not None and contains_character.lower() not in value.lower():
            match = False

        if match:
            filtered.append(item)

    if not filtered:
        raise BadRequestException("No string matches the given filters.")

    data = {
        "data": filtered,
        "count": len(filtered),
        "filters_applied": {
            "is_palindrome": is_palindrome,
            "min_length": min_length,
            "max_length": max_length,
            "word_count": word_count,
            "contains_character": contains_character
        }
    }

    return JSONResponse(status_code=200, content=data)


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


def parse_natural_language_query(query: str) -> Dict[str, Any]:
    filters = {}
    query_lower = query.lower()

    if "palindrome" in query_lower or "palindromic" in query_lower:
        filters["is_palindrome"] = True

    if "single word" in query_lower:
        filters["word_count"] = 1

    longer_match = re.search(r"longer than (\d+)", query_lower)
    if longer_match:
        filters["min_length"] = int(longer_match.group(1)) + 1

    shorter_match = re.search(r"shorter than (\d+)", query_lower)
    if shorter_match:
        filters["max_length"] = int(shorter_match.group(1)) - 1

    contains_match = re.search(r"contain(?:s|ing)\s+(?:letter\s+)?([a-z])", query_lower)
    if contains_match:
        filters["contains_character"] = contains_match.group(1)

    return filters


@limiter.limit("12/minute")
@app.get("/strings/filter-by-natural-language")
def filter_by_natural_language(request: Request, query: str = Query(..., description="Natural language filter query")):
    if not query:
        raise BadRequestException("The 'query' parameter is required.")

    filters = parse_natural_language_query(query)

    # Apply parsed filters
    filtered = []
    for item in StringDB:
        value = item.get("value", "")
        length = len(value)
        wc = len(value.split())
        palindrome_check = value.lower() == value.lower()[::-1]

        match = True

        if "is_palindrome" in filters and filters["is_palindrome"] != palindrome_check:
            match = False

        if "min_length" in filters and length < filters["min_length"]:
            match = False

        if "max_length" in filters and length > filters["max_length"]:
            match = False

        if "word_count" in filters and wc != filters["word_count"]:
            match = False

        if "contains_character" in filters and filters["contains_character"] not in value.lower():
            match = False

        if match:
            filtered.append(item)

    if not filtered:
        raise NotFoundException("No strings match the given natural language query.")

    return JSONResponse(
        status_code=200,
        content={
            "data": filtered,
            "count": len(filtered),
            "interpreted_query": {
                "original_query": query,
                "parsed_filters": filters
            }
        }
    )