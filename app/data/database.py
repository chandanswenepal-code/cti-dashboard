from sqlalchemy import create_engine, Column, String, Integer, DateTime, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()
engine = create_engine("sqlite:///cti_data.db", echo=False)
Session = sessionmaker(bind=engine)

class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator = Column(String(500), index=True, unique=True)
    ioc_type = Column(String(50))
    pulse_name = Column(Text)
    threat_actor = Column(String(200))
    tags = Column(Text)
    abuse_score = Column(Float, default=0)
    country = Column(String(10))
    isp = Column(String(200))
    total_reports = Column(Integer, default=0)
    mitre_tactic = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(engine)

def get_session():
    return Session()