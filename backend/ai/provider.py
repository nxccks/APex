from google import genai
from abc import ABC, abstractmethod
from backend.config import config
from backend.ai.prompts import SYSTEM_PROMPT, BYPASS_REQUEST_PROMPT

class AIProvider(ABC):
    @abstractmethod
    def generate_hook(self, smali_code: str, category: str) -> str:
        pass

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.0-flash" # Defaulting to current stable fast model

    def generate_hook(self, smali_code: str, category: str) -> str:
        prompt = BYPASS_REQUEST_PROMPT.format(smali_code=smali_code, category=category)
        response = self.client.models.generate_content(
            model=self.model_id,
            config={'system_instruction': SYSTEM_PROMPT},
            contents=prompt
        )
        
        # Extract the code block from the response
        import re
        match = re.search(r'```javascript\n(.*?)\n```', response.text, re.DOTALL)
        if match:
            return match.group(1)
        return response.text

class AIProviderFactory:
    @staticmethod
    def get_provider() -> AIProvider:
        if config.AI_PROVIDER == "google":
            return GeminiProvider(config.GOOGLE_API_KEY)
        # Placeholder for other providers
        raise ValueError(f"Unsupported AI provider: {config.AI_PROVIDER}")
