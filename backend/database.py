import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://saidheerajreddy@localhost:5432/sentinelai"
)

engine = create_engine(
    DATABASE_URL,
    echo=False
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class Incident(Base):

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

    prediction = Column(String)
    threat_probability = Column(Float)
    anomaly = Column(String)
    risk_score = Column(Float)
    severity = Column(String)
    priority = Column(String)

    status = Column(
        String,
        default="OPEN"
    )

    source_ip = Column(String)
    destination_ip = Column(String)
    destination_port = Column(Integer)

    risk_factors = Column(JSON)
    investigation = Column(JSON)
    threat_graph = Column(JSON)


def create_tables():

    Base.metadata.create_all(
        bind=engine
    )


def get_db():

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()
