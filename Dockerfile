FROM ubuntu

MAINTAINER @frikkylikeme

ADD requirements.txt /offense_api/requirements.txt
ADD setup /offense_api/setup
RUN /offense_api/setup

WORKDIR /offense_api/

COPY database/ /offense_api/database/
COPY dependencies/ /offense_api/dependencies/
COPY log/ /offense_api/log/

ADD get_offense.py /offense_api/get_offense.py

CMD ["python", "get_offense.py"]
