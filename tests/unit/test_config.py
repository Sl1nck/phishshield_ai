from phishshield.config.settings import Settings


def test_settings_load_success(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "key_de_prueba_valida")
    monkeypatch.setenv("GEMINI_PRIMARY_MODEL", "gemini-2.0-flash")
    monkeypatch.setenv("GEMINI_FALLBACK_MODEL", "gemini-2.0-flash-lite")

    app_settings = Settings(_env_file=None)
    assert app_settings.GEMINI_API_KEY == "key_de_prueba_valida"
    assert app_settings.GEMINI_PRIMARY_MODEL == "gemini-2.0-flash"
    assert app_settings.GEMINI_FALLBACK_MODEL == "gemini-2.0-flash-lite"


def test_settings_default_values(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_PRIMARY_MODEL", raising=False)
    monkeypatch.delenv("GEMINI_FALLBACK_MODEL", raising=False)

    app_settings = Settings(_env_file=None)
    assert app_settings.GEMINI_API_KEY == ""
    assert app_settings.GEMINI_PRIMARY_MODEL == "gemini-2.0-flash"
    assert app_settings.GEMINI_FALLBACK_MODEL == "gemini-2.0-flash-lite"
    assert app_settings.LOG_LEVEL == "INFO"