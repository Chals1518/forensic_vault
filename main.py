# main.py
from fastapi import FastAPI
from dotenv import load_dotenv
from database import init_db
from routes import auth, cases, audit, samples, files

load_dotenv()

app = FastAPI(
    title="ForensicVault API",
    description="Secure encrypted storage for forensic case files and chain-of-custody logs.",
    version="2.0.0"
)

init_db()

app.include_router(auth.router)
app.include_router(cases.router)
app.include_router(audit.router)
app.include_router(samples.router)
app.include_router(files.router)


@app.get("/")
def root():
    return {
        "project": "ForensicVault API",
        "version": "2.0.0",
        "status" : "running"
    }