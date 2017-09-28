# Introduction

This is an overview of the recent offenses in QRadar. 

## Usage
$ pip install -r requirements.txt<br>
$ python get\_offense.py

# Docker usage
$ sudo docker build . -t offense<br>
$ sudo docker run -d -v $(pwd)/log:/offense_api/log -v $(pwd)/database:/offense_api/database/ offense<br>

## Database

The database for all the different instances of QRadar is available under database/customer_values.db and is automatically generated when you first run get_offense.py. 

## Logging 

Logging is done to the log/alarm.log file. It contains all information about what the program doen in realtime so if you want a realtime log just tail -f log/alarm.log.

If -v (verbose) is not present, offenses can only be read from log/offenses.log.

## Extra rules feature

The program is made in a way that you can change the outcome of alarms in real time with the use of the database/customer.json file. This can be done using the "rules" part, where you decide what fields to be checked. It used to have regex structure, but due to some faults in the python regex library this was no longer an option. It's now done by entering the field, e.g. "description": "firewall|login", where the program looks for any of those words within the offense generated. 

Further you can make as many rules as you want, split on comma, but all of the criteria within one {} has to match exactly. The program will look for a timedifference in the file to see if a reload is necessary.

## Contributors

@frikkylikeme \o/
