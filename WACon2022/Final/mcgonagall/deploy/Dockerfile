FROM ubuntu:20.04
RUN apt-get update
RUN apt-get install socat python3 python3-pip -y
RUN pip3 install pycryptodome ecdsa
WORKDIR /app
COPY ./chall.py /app
COPY ./flag.py /app
EXPOSE 13337
CMD ["socat", "TCP-LISTEN:13337,reuseaddr,fork", "EXEC:python3 chall.py,nofork,stderr"]
