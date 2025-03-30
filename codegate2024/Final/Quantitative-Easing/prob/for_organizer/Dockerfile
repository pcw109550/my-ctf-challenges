FROM python:3.11

RUN apt update
RUN apt-get install -y socat

WORKDIR /crypto

COPY ./src /crypto

RUN python3 -m pip install -r requirements.txt

EXPOSE 13337

CMD ["socat", "-t30", "-T30", "TCP-LISTEN:13337,reuseaddr,fork", "EXEC:./init.sh"]
