FROM sagemath/sagemath:10.0

USER root

RUN apt update
RUN apt-get install -y socat python3
RUN apt-get install -y python3-pip

RUN sage -c "exit"

WORKDIR /app
COPY --link chall.sage flag.txt init.sh pow.py requirements.txt ./

RUN python3 -m pip install --no-cache-dir -r requirements.txt

EXPOSE 10955

CMD ["socat", "-t900", "-T900", "TCP-LISTEN:10955,reuseaddr,fork", "EXEC:./init.sh"]
