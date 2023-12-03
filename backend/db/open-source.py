from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Date, Boolean, ForeignKey
import os


load_dotenv()
# Declare the database engine
engine = create_engine("mysql://", os.getenv('DATABASE_CONNECTION_URL'), echo=True)

# Create a declarative base class for tables
Base = declarative_base()

# Define the 'Users' table
class User(Base):
    __tablename__ = 'Users'
    UserID = Column(Integer, primary_key=True, autoincrement=True)
    Username = Column(String(255), nullable=False)
    Password = Column(String(255), nullable=False)
    IsGoogleAccount = Column(Boolean, nullable=False)
    GoogleToken = Column(String(255), nullable=True)  # Add Google token field if he used google account
    Email = Column(String(255))
    VirusTotalAPIKey = Column(String(255))

# Define the 'Websites' table
class Website(Base):
    __tablename__ = 'Websites'
    WebsiteID = Column(Integer, primary_key=True, autoincrement=True)
    URL = Column(String(255), nullable=False)
    LastScannedDate = Column(Date, nullable=False)
    IsSecure = Column(Boolean, nullable=False)

# Define the 'Scans' table
class Scan(Base):
    __tablename__ = 'Scans'
    ScanID = Column(Integer, primary_key=True, autoincrement=True)
    WebsiteID = Column(Integer, ForeignKey('Websites.WebsiteID'), nullable=False)
    ScanDate = Column(Date, nullable=False)
    PhishingScore = Column(Integer, nullable=False)

# Define the 'EmailScans' table
class EmailScan(Base):
    __tablename__ = 'EmailScans'
    EmailScanID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer, ForeignKey('Users.UserID'), nullable=False)
    LastScanDate = Column(Date, nullable=False)
    IsSecure = Column(Boolean, nullable=False)
    IsSuspiciousEmailAddress = Column(Boolean, nullable=False)
    SenderAddress = Column(String(255), nullable=True)
    IsSenderBlacklisted = Column(Boolean, nullable=False)

# Define the 'WebsiteStatistics' table
class WebsiteStatistic(Base):
    __tablename__ = 'WebsiteStatistics'
    StatisticID = Column(Integer, primary_key=True, autoincrement=True)
    WebsiteID = Column(Integer, ForeignKey('Websites.WebsiteID'), nullable=False)
    VisitDate = Column(Date, nullable=False)
    IsSafe = Column(Boolean, nullable=False)
    IsMalicious = Column(Boolean, nullable=False)
    IsBlacklisted = Column(Boolean, nullable=False)
    IsWhitelisted = Column(Boolean, nullable=False)

def create_user(username, password, email, is_google_account, google_token):
    session = sessionmaker(bind=engine)()

    if is_google_account:
        user = User(username=username, password=password, email=email, google_token=google_token)
    else:
        user = User(username=username, password=password, email=email)

    session.add(user)
    session.commit()


# Create the tables in the database
Base.metadata.create_all(engine)