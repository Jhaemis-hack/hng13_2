# String Analysis API

A **FastAPI**-powered RESTful service that allows users to submit, analyze, retrieve, and manage strings with rich metadata, such as SHA256 hashes, palindrome detection, word count, and character frequency mapping.

---

## Features

- **Store and Retrieve Strings:** Save unique strings and retrieve their computed properties.  
- **String Properties:** Automatically calculates length, palindrome status, word count, character frequency, and SHA256 hash.  
- **Filtering:** Filter stored strings based on multiple criteria such as length, palindrome status, character inclusion, etc.  
- **Rate Limiting:** Protects routes using `slowapi` to prevent abuse (default: 8 requests per minute).  
- **Custom Exceptions:** Includes clean and descriptive error messages with proper status codes.  
- **In-Memory Database:** Uses a simple Python list (`StringDB`) to simulate a temporary database.  

---

## Tech Stack

| Layer | Technology |
|--------|-------------|
| Backend Framework | FastAPI |
| Rate Limiting | slowapi |
| Security | helmet, CORS |
| HTTP Server | Uvicorn |
| Data Handling | Pydantic Models |

---

##  Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/string-analysis-api.git
cd string-analysis-api
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Example `requirements.txt` content:
```
fastapi
uvicorn
slowapi
pydantic
python-dotenv
```

### 4. Run the Server

```bash
uvicorn main:app --reload --port 8080
```

Your API will be live at:
```
http://127.0.0.1:8080
```

---

## API Documentation

FastAPI automatically generates documentation for you:

- **Swagger UI:** [http://127.0.0.1:8080/docs](http://127.0.0.1:8080/docs)
- **ReDoc:** [http://127.0.0.1:8080/redoc](http://127.0.0.1:8080/redoc)

---

## Endpoints Overview

### 1. **POST /strings**
Store a new string and compute its metadata.

#### Example Request
```json
{
  "value": "boob"
}
```

#### Example Response
```json
{
  "id": "e99d55248f67be7623332be8dabcd143ce2495eb923860b4ed0d963621ece901",
  "value": "boob",
  "properties": {
    "length": 4,
    "is_palindrome": true,
    "unique_characters": 0,
    "word_count": 4,
    "sha256_hash": "e99d55248f67be7623332be8dabcd143ce2495eb923860b4ed0d963621ece901",
    "character_frequency_map": {
      "b": 2,
      "o": 2
    }
  },
  "created_at": "2025-10-22T18:12:30.354308Z"
}
```

---

### 2. **GET /strings**
Filter stored strings based on query parameters.

#### Example Query
```
/strings?is_palindrome=true&min_length=2&max_length=6&word_count=5&contains_character=b
```

#### Example Response
```json
{
  "data": [
    {
      "id": "e99d55248f67be7623332be8dabcd143ce2495eb923860b4ed0d963621ece901",
      "value": "boob",
      "properties": {
        "length": 4,
        "is_palindrome": true,
        "unique_characters": 0,
        "word_count": 4,
        "sha256_hash": "e99d55248f67be7623332be8dabcd143ce2495eb923860b4ed0d963621ece901",
        "character_frequency_map": {
          "b": 2,
          "o": 2
        }
      },
      "created_at": "2025-10-22T18:12:30.354308Z"
    }
  ],
  "count": 1,
  "filters_applied": {
    "is_palindrome": true,
    "min_length": 2,
    "max_length": 6,
    "word_count": 5,
    "contains_character": "b"
  }
}
```

---

### 3. **DELETE /strings/{string_value}**
Deletes a string entry if it exists.

#### Example
```
DELETE /strings/boob
```

#### Response
```
204 No Content
```

---

##  Error Handling

The API uses a consistent error response model for validation and runtime errors.

| Error | HTTP Code | Description |
|--------|------------|-------------|
| `NotFoundException` | 404 | When the string or query result is not found |
| `ValidationError` | 400 | When a required field is missing or invalid |
| `RateLimitExceeded` | 429 | When request frequency exceeds allowed limit |

---

## Notes

- This project uses **in-memory storage**, meaning all data resets when the server restarts.
- You can extend this API by integrating a database like **MongoDB** or **PostgreSQL**.
- Modify the `StringDB` list to connect with your preferred data persistence layer.

---

## Author

**James Kehinde**  
Built with ❤️ using FastAPI  
[GitHub](https://github.com/your-username)

