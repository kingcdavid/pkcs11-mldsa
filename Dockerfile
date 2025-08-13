from debian:trixie


ARG SOFTHSM2_VERSION=mldsa

ENV SOFTHSM2_VERSION=${SOFTHSM2_VERSION}


# install build dependencies
RUN apt-get update && apt-get install -y \
        build-essential \
        autoconf \
        automake \
        git \
        libtool \
        libssl-dev \
        openssl \
        golang \
        opensc

# build and install SoftHSM2
RUN git clone https://github.com/antoinelochet/SoftHSMv2.git

RUN cd SoftHSMv2 && git switch ${SOFTHSM2_VERSION} \
    && sh autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install

WORKDIR /root

