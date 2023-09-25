from sqlalchemy import create_engine, ForeignKey, Column, String, Integer, CHAR
from sqlalchemy.orm import sessionmaker, declarative_base
from flask_login import UserMixin
populate = True
engine = create_engine("sqlite:///message2.db", echo=True)
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)

    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', password='{self.password}')>"
    

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    message = Column(String)

    def __repr__(self):
        return f"<User(id='{self.id}', user_id='{self.user_id}', message='{self.message}')>"
    

Base.metadata.create_all(engine)