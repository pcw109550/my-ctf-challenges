FROM ubuntu:20.04
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
       apt-get install git build-essential cmake git pkg-config libboost-dev libboost-date-time-dev \
       libboost-system-dev libboost-filesystem-dev libboost-thread-dev libboost-chrono-dev \
       libboost-serialization-dev liblog4cpp5-dev libuhd-dev gnuradio-dev gr-osmosdr \
       libblas-dev liblapack-dev libarmadillo-dev libgflags-dev libgoogle-glog-dev \
       libgnutls-openssl-dev libpcap-dev libmatio-dev libpugixml-dev libgtest-dev \
       libprotobuf-dev protobuf-compiler python3-mako -y

WORKDIR /app
RUN git clone https://github.com/gnss-sdr/gnss-sdr && cd gnss-sdr && git checkout next
RUN cd /app/gnss-sdr/build && cmake .. && make && make install 

CMD /bin/bash
