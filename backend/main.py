from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.db import init_db
from routes import auth


app = FastAPI()

origins = ["http://localhost", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)


app.include_router(auth.router, prefix="/auth")



@app.get("/")
async def main():
    return {"Hello from PC": " Hello from Dockerrrrr"}



init_db()
