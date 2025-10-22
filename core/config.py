from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    cat_api_url: str

    model_config = SettingsConfigDict(env_file=".env")