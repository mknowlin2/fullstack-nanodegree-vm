#!/usr/bin/env python3
#
# The Catalog Web application data access layer.
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.database_setup import Base, User

'''Set up database engine and database session '''
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def get_users():
    '''Retrieve all records from the User table'''
    users = session.query(User).all()
    return users

def get_user_by_id(id):
    '''Retrieve user by id from the User table'''
    try:
        user = session.query(User).filter_by(id=id).one()
        return user
    except:
        return None

def get_user_by_username(username):
    '''Retrieve user by name from the User table'''
    try:
        user = session.query(User).filter_by(username=username).one()
        return user
    except:
        return None

def add_user(username, password):
    '''Insert new user into the User table'''
    newUser = User(username=username)
    newUser.hash_password(password)
    session.add(newUser)
    session.commit()
