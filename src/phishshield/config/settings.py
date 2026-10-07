from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    GEMINI_API_KEY: str = ""
    # Actualizamos a los modelos 2.0 que soportan correctamente el esquema JSON
    GEMINI_PRIMARY_MODEL: str = "gemini-2.0-flash"
    GEMINI_FALLBACK_MODEL: str = "gemini-2.0-flash-lite" 
    LOG_LEVEL: str = "INFO"

    # Configuración para que lea automáticamente las variables desde tu archivo .env
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

# Instancia global de configuración que importarás en otros archivos
settings = Settings() 