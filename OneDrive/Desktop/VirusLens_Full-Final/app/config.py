# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    VT_API_KEY: str | None = Field(default=None)
    URLSCAN_API_KEY: str | None = Field(default=None)
    OTX_API_KEY: str | None = Field(default=None)
    MOCK_MODE: bool = Field(default=False)

settings = Settings()
