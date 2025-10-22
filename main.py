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

#
# @limiter.limit("8/minute")
# @app.post("/strings")
# async def analyze_string(request: Request, body: Value):
#     provided_string = body.value
#
#     for string in range(len(StringDB)):
#         index_item = StringDB[string]
#         if index_item['value'] == provided_string:
#             raise ConflictException("String already exists in the system")
#
#     hashed_string = get_string_hash(provided_string)
#     no_space_string = provided_string.replace(" ", "")
#     provided_string_char_collection: list[Any] = []
#     for char in no_space_string:
#         provided_string_char_collection.append(char)
#
#     char_freq: dict[str, int] = {}
#     for letter in provided_string_char_collection:
#         duplicate_count = provided_string_char_collection.count(letter)
#         char_freq[letter] = duplicate_count
#
#     # reversed_char_string = reversed_string(provided_string)
#     # palindrome = reversed_char_string == provided_string
#
#     palindrome = provided_string.lower().replace(" ", "") == reversed_string(provided_string.lower().replace(" ", ""))
#
#     data = {
#         "id": hashed_string,
#         "value": provided_string,
#         "properties": {
#             "length": len(provided_string_char_collection),
#             "is_palindrome": palindrome,
#             "unique_characters": len(set(provided_string_char_collection)),
#             "word_count": len(provided_string.split()),
#             "sha256_hash": hashed_string,
#             "character_frequency_map": char_freq,
#         },
#         "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
#     }
#     StringDB.append(data)
#     return JSONResponse(content=data, status_code=201, media_type="application/json")

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
async def filter_string(
    request: Request,
    is_palindrome: bool = Query(..., description="is_palindrome (true/false)"),
    min_length: int = Query(..., description="Minimum string length (inclusive)"),
    max_length: int = Query(..., description="Maximum string length (inclusive)"),
    word_count: int = Query(..., description="Exact word count"),
    contains_character: str = Query(..., min_length=1, description="A single character to search for"),
):
    # Validate contains_character length
    if len(contains_character) != 1:
        raise BadRequestException("contains_character must be a single character.")

    # Normalize search char for case-insensitive check
    search_char = contains_character.lower()

    # Validate min/max semantics
    if min_length < 0 or max_length < 0:
        raise BadRequestException("min_length and max_length must be non-negative integers.")
    if min_length > max_length:
        raise BadRequestException("min_length cannot be greater than max_length.")

    filtered = []
    for item in StringDB:
        props = item["properties"]

        # inclusive length check
        length_ok = (min_length <= props["length"] <= max_length)
        if props["is_palindrome"] != is_palindrome or not length_ok:
            continue

        # exact word count
        if props["word_count"] != word_count:
            continue

        # contains_character case-insensitive
        if search_char not in item["value"].lower():
            continue

        filtered.append(item)

    # return consistent response shape even when empty
    response = {
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
    return JSONResponse(content=response, status_code=200, media_type="application/json")



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

# @limiter.limit("8/minute")
# @app.get("/strings/filter-by-natural-language")
# async def filter_by_natural_language(
#     request: Request,
#     query: str = Query(..., description="A natural language filter query")
# ):
#     q = query.lower().strip()
#     parsed = {}
#
#     if "palindrom" in q:
#         parsed["is_palindrome"] = True
#
#     if "single word" in q or "one word" in q or "single-word" in q:
#         parsed["word_count"] = 1
#
#     if "longer than" in q:
#         try:
#             tail = q.split("longer than", 1)[1]
#             num = int("".join(ch for ch in tail if ch.isdigit()))
#             parsed["min_length"] = num + 1
#         except Exception:
#             raise BadRequestException("Unable to parse numeric length from query.")
#
#     if "containing the letter" in q:
#         try:
#             tail = q.split("containing the letter", 1)[1].strip()
#             if not tail:
#                 raise ValueError
#             parsed["contains_character"] = tail[0]
#         except Exception:
#             raise BadRequestException("Unable to parse letter from query.")
#
#
#     if "containing " in q and "containing the letter" not in q:
#         # crude attempt to get single char after 'containing '
#         try:
#             tail = q.split("containing", 1)[1].strip()
#             # pick first token's first char
#             parsed["contains_character"] = tail.split()[0][0]
#         except Exception:
#             pass
#
#     if not parsed:
#         raise BadRequestException("Unable to parse natural language query")
#
#     filtered = []
#     for item in StringDB:
#         props = item["properties"]
#
#         if "is_palindrome" in parsed and props["is_palindrome"] != parsed["is_palindrome"]:
#             continue
#         if "word_count" in parsed and props["word_count"] != parsed["word_count"]:
#             continue
#         if "min_length" in parsed and props["length"] < parsed["min_length"]:
#             continue
#         if "contains_character" in parsed and parsed["contains_character"].lower() not in item["value"].lower():
#             continue
#
#         filtered.append(item)
#
#     if not filtered:
#         raise NotFoundException("No String matches this queries in the system.")
#
#     response = {
#         "data": filtered,
#         "count": len(filtered),
#         "interpreted_query": {
#             "original": query,
#             "parsed_filters": parsed
#         }
#     }
#     return JSONResponse(content=response, status_code=200, media_type="application/json")



def parse_natural_language_query(request: Request, query_string: str) -> Dict[str, Any]:

    filters = {}
    query_lower = query_string.lower()

    # Check for palindrome
    if 'palindrome' in query_lower or 'palindromic' in query_lower:
        filters['is_palindrome'] = True

    # Check for single word
    if 'single word' in query_lower:
        filters['word_count'] = 1

    # Check for "longer than X characters"
    longer_match = re.search(r'longer than (\d+)', query_lower)
    if longer_match:
        x = int(longer_match.group(1))
        filters['min_length'] = x + 1

    # Check for "shorter than X"
    shorter_match = re.search(r'shorter than (\d+)', query_lower)
    if shorter_match:
        x = int(shorter_match.group(1))
        filters['max_length'] = x - 1

    # Check for "contains letter X" or "containing X"
    contains_match = re.search(r'contain(?:s|ing)\s+(?:letter\s+)?([a-z])', query_lower)
    if contains_match:
        filters['contains_character'] = contains_match.group(1)

    # Check for "first vowel"
    if 'first vowel' in query_lower:
        filters['contains_character'] = 'a'

    return filters


@limiter.limit("8/minute")
@app.get("/strings/filter-by-natural-language")
def filter_by_natural_language(request: Request,query: str = Query(..., description="Natural language filter query")):
    """
    GET /strings/filter-by-natural-language

    Parses a natural language query (e.g., "all single word palindromic strings")
    into filters, applies them to StringDB, and returns matching results.
    """
    if not query:
        raise BadRequestException("The 'query' parameter is required.")

    try:
        parsed_filters = parse_natural_language_query(query)
    except Exception as e:
        raise BadRequestException(f"Unable to parse query: {str(e)}")

    # Check for conflicting filters
    if 'min_length' in parsed_filters and 'max_length' in parsed_filters:
        if parsed_filters['min_length'] > parsed_filters['max_length']:
            raise BadRequestException("min_length cannot be greater than max_length.")

    # Apply filters to StringDB
    filtered_results = []

    for item in StringDB:
        value = item.get("value", "")
        props = item.get("properties", {})
        length = len(value)
        word_count = len(value.split())
        is_palindrome = value.lower() == value.lower()[::-1]

        match = True

        # Apply filters
        if 'is_palindrome' in parsed_filters and parsed_filters['is_palindrome'] != is_palindrome:
            match = False

        if 'min_length' in parsed_filters and length < parsed_filters['min_length']:
            match = False

        if 'max_length' in parsed_filters and length > parsed_filters['max_length']:
            match = False

        if 'word_count' in parsed_filters and word_count != parsed_filters['word_count']:
            match = False

        if 'contains_character' in parsed_filters and parsed_filters['contains_character'] not in value.lower():
            match = False

        if match:
            filtered_results.append(item)

    response = {
        "data": filtered_results,
        "count": len(filtered_results),
        "interpreted_query": {
            "original_query": query,
            "parsed_filters": parsed_filters
        }
    }

    return JSONResponse(status_code=200, content=response)
