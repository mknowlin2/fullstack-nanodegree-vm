#!/usr/bin/env python3
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


def get_user(user_id):
    '''Retrieve user by id from the User table'''
    user = session.query(User).filter_by(id=user_id).one()
    return user


def add_user(user_name):
    '''Insert new user into the User table'''
    newUser = User(name=user_name)
    session.add(newUser)
    session.commit()
