from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import models
import uvicorn
from database import engine
from routers import auth

app = FastAPI(debug=True)

# Your existing code for routes and other configurations

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

origins = [
    "http://localhost:4200"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
models.Base.metadata.create_all(bind=engine)
app.include_router(auth.router)
