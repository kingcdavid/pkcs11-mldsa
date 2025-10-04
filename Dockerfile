from debian:trixie


ARG SOFTHSM2_VERSION=ml-dsa-pr

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
        opensc \
        rsyslog

# build and install SoftHSM2
RUN git clone https://github.com/antoinelochet/SoftHSMv2.git

RUN cd SoftHSMv2 && git switch ${SOFTHSM2_VERSION} \
    && sh autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install

RUN pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --init-token --slot 0 --label tsa --so-pin 0000
RUN pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --init-pin --slot-index 0 --pin 1234 --so-pin 0000

WORKDIR /root

