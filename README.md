# Device Grant SEC Simulation
## Table of contents
* [General info](#general-info)
* [Technologies](#technologies)
* [Setup](#setup)

## General info
This project simulates feasible attack scenarios on OAuth Device Authorization Grant ("Device Flow").
It is part of a research project with the goal to examine the practical security of the Device Flow.
The Grant enables a user to connect devices that lack an appropriate interface for password input or other authentication procedures (e.g. Hardware Token) to his account at an online service. 

The simulation includes an authentication server (AS), a client device (in form of a simple web application), and an attacker. The attack can be configured for various attack vectors. 
	
## Technologies
Project is created with:
* Django version: 3.1.3
* Celery version: 5.0.2
* Redis server version: 5.0.7

## Setup
### Install requirements
Navigate to root of the project and run:

 - python -m pip install -r requirements.txt
 - python manage.py migrate

### Run server
Run the following commands in three separate shells:

- redis-server
- celery -A device_grant_sec_simulation worker -l info --concurrency=20
- python manage.py runserver

Open link http://127.0.0.1:8000/ in browser and follow further instructions there. 

A valid user in the database is username = Bob, password = good, or username = Eve, password = evil
