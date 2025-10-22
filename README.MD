# My Profile API

A **FastAPI-based web application** that serves my profile details, health checks, and an external cat fact using rate limiting and proper exception handling. It demonstrates clean API structure, modular configuration, and integration with external services.

---

## Project Overview

This API provides the following routes:

| Endpoint | Method | Description |
|-----------|--------|--------------|
| `/` | GET | Welcome route |
| `/health` | GET | Health check endpoint |
| `/me` | GET | Returns profile details and a random cat fact |

---

## Features

- **FastAPI** for modern async web framework performance.
- **SlowAPI** for rate limiting.
- **CORS middleware** for cross-origin requests.
- **Config management** using Pydantic settings.
- **Custom error handling** through reusable error handler modules.
- **Asynchronous HTTP client integration.**

---

## Project Structure

```
hng13_1/
│
├── core/
│   ├── __init__.py
│   ├── config.py
│   ├── error_handlers.py
│   ├── exceptions.py
│
├── services/
│   ├── __init__.py
│   ├── http_client.py
│
├── main.py
├── test_main.py
├── requirements.txt
└── README.md
```

---

## Installation Guide

### Clone the Repository

```bash
git clone https://github.com/yourusername/hng13_1.git
cd hng13_1
```

### Create a Virtual Environment

```bash
python -m venv .ve
```

Activate it:

**Windows**
```bash
.ve\Scripts\activate
```

**Mac/Linux**
```bash
source .ve/bin/activate
```

### Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Ensure your `requirements.txt` includes:

```
fastapi
uvicorn[standard]
slowapi
pydantic_settings
httpx[h2]
```

---

## Running the Application Locally

Once installed, run the app using:

```bash
uvicorn main:app --reload
```

The server starts at:
👉 http://127.0.0.1:8000

---

## API Endpoints Overview

| Endpoint | Description | Example |
|-----------|--------------|----------|
| `/` | Welcome message | GET `/` |
| `/health` | Health status | GET `/health` |
| `/me` | Profile + random cat fact | GET `/me` |

---

## Example Response

**GET `/me`**

```json
{
  "status": "success",
  "user": {
    "email": "gbemilekekenny@gmail.com",
    "name": "James Kehinde",
    "stack": "NodeJs"
  },
  "timestamp": "2025-10-17T23:30:15Z",
  "fact": "Cats sleep for around 13 to 16 hours a day."
}
```

---

## Deployment Notes

If deploying (e.g. Render, Railway, etc.), ensure your **Start Command** is:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

And **Python version** is `>=3.12`.

---

## Author

**James Kehinde**  
Email: gbemilekekenny@gmail.com  
Stack: NodeJS / Full Stack Developer

---

## License

This project is licensed under the MIT License.
