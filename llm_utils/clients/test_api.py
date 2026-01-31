"""Quick manual smoke test for the configured LLM client."""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    # Allow running this file directly while still importing the local package.
    sys.path.insert(0, _ROOT)

from llm_utils import get_default_client

client = get_default_client()
text = client.chat_text(prompt="给我一个一句话总结", system="你是一个严谨的代码助手")
print(text)
