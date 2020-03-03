# sudo docker build -t planemarket .
# sudo docker run -d -p 1024:1024 --rm -it planemarket

FROM debian:testing-20191118

RUN apt-get update

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

COPY plane_market .
COPY flag .
COPY ynetd .

RUN chown -R root:root /home/ctf

USER ctf
CMD ./ynetd -p 1024 ./plane_market
