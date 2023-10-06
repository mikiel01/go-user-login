DROP DATABASE IF EXISTS arrayDB;    

CREATE DATABASE arrayDB;  
\c arrayDB; 

CREATE TABLE IF NOT EXISTS Users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE,
    password VARCHAR(128),
    salt VARCHAR(32)
)