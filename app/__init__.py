from google.adk.apps import App
from .agent import root_agent

app = App(
    name="app",
    root_agent=root_agent
)
