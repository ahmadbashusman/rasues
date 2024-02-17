# RASUES 

The update is based on the  https://github.com/sbabic/meta-swupdate-boards.

The attestation is based on the https://github.com/Fraunhofer-SIT/charra.

The watchdog timer can used based on https://github.com/siemens/efibootguard

# meta-swupdate-rpi
The project allows to include swupdate in the yocto build for the Raspberry Pi4 and use it in pair with update-server feature.
See update-server repository for details


## Getting Started
This layer depends on:

* URI: git://git.yoctoproject.org/poky
  * branch: master
  * revision: HEAD

* URI: git://github.com/agherzan/meta-raspberrypi.git
  * branch: master
  * revision: HEAD

To build run:

```
	bitbake update-image
```

Above will generate a `swu` file suitable for usage with SWUpdate on
your device.

Note that `update-image` depends on `ext4.gz` and you must make sure
that it is part of `IMAGE_FSTYPES`.

For usage with Raspberry Pi one must add the following to `local.conf`

	RPI_USE_U_BOOT = "1"


## Installing
sudo apt-get update
sudo apt-get install \
     gawk wget git-core diffstat unzip texinfo gcc-multilib \
     build-essential chrpath socat cpio \
     python python3 python3-pip python3-pexpect \
     xz-utils debianutils iputils-ping \
     python3-git python3-jinja2 libegl1-mesa libsdl1.2-dev
     
### Clone all meta-layers

mkdir yocto && cd yocto
mkdir layers && cd layers
git clone git://git.yoctoproject.org/poky -b zeus
git clone git://github.com/openembedded/meta-openembedded.git -b zeus
git clone https://github.com/agherzan/meta-raspberrypi.git -b zeus
git clone https://github.com/sbabic/meta-swupdate -b zeus

git clone https://github.com/sbabic/meta-swupdate-boards.git -b master

cd ..
. layers/poky/oe-init-build-env build


### Add the following to build/conf/local.conf (Raspberry pi doesn't use uboot bootloader by default. swupdate requires ext4.gz image.)

RPI_USE_U_BOOT = "1"
IMAGE_FSTYPES = "rpi-sdimg ext4.gz"
PREFERRED_PROVIDER_u-boot-fw-utils = "libubootenv"



## Built With
* [SW Update](https://sbabic.github.io/swupdate/) - Update client for embedded linux
* [Raspberry Pi](https://www.raspberrypi.org) - Raspberry Pi 4 adapted kernel and firmware

## Limitations
## Versioning

We use [SemVer](http://semver.org/) for versioning. 


## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT license. See the [COPYING.MIT](COPYING.MIT) file for details.





# CHARRA: CHAllenge-Response based Remote Attestation with TPM 2.0 as Passport Model

![CHARRA Logo](charra-logo_small.png)

This is a proof-of-concept implementation of the "Challenge/Response Remote Attestation" interaction model of the [IETF RATS](https://datatracker.ietf.org/wg/rats/about/) [Reference Interaction Models for Remote Attestation Procedures](https://datatracker.ietf.org/doc/draft-ietf-rats-reference-interaction-models/) using TPM 2.0. The [IETF Remote Attestation Procedures (RATS)](https://datatracker.ietf.org/wg/rats/about/) working group standardizes formats for describing assertions/claims about system components and associated evidence; and procedures and protocols to convey these assertions/claims to relying parties. Given the security and privacy sensitive nature of these assertions/claims, the working group specifies approaches to protect this exchanged data.

This proof-of-concept implementation realizes the Attesting Computing Environment—a Computing Environment capable of monitoring and attesting a target Computing Environment—as well as the target Computing Environment itself, as described in the [RATS Architecture](https://datatracker.ietf.org/doc/rfc9334/).
CHARRA-PM is a development of the Passport Model, also defined by RATS workgroup documents using the source code from CHARRA and developing functions and interactions into a new model.

## Build and Run

Adding passport model (as its based on CHARRA) comes with a Docker test environment and Docker helper scripts to build and run it in Docker.
<!-- It is also possible to build and run CHARRA manually. -->
All commands assume to be executed in [Bash](https://www.gnu.org/software/bash/), the Bourne-again shell.

### Using Docker

Running CHARRA-PM in Docker is the "quickstart" way of running it.
This way, you do not need to install all the dependencies into your system in order to try CHARRA-PM.
All steps to get it up and running are described in the following.

#### Build the Docker Base Image

The CHARRA-PM `Dockerfile` uses on the official [*tpm2software/tpm2-tss* Docker images](https://github.com/tpm2-software/tpm2-software-container.git) as a basis.
Recently, these official images were removed from [Docker Hub](https://hub.docker.com/r/tpm2software/tpm2-tss>).
That is why the Docker base image for CHARRA-PM must now be built manually.

1. Install [Docker](https://docs.docker.com/engine/install/).

2. Install dependencies (*make* and *m4*):

       ## On Ubuntu
       sudo apt install make m4

       ## On Fedora
       sudo dnf install make m4

3. Clone the [TPM2 Software Container](https://github.com/tpm2-software/tpm2-software-container) repository:

       git clone 'https://github.com/tpm2-software/tpm2-software-container.git' \
           'tmp/tpm2-software-container'
       pushd 'tmp/tpm2-software-container'

4. Create `*.docker` files:

       make

5. Build Docker image:

       docker build -t 'tpm2software/tpm2-tss:ubuntu-20.04' -f ubuntu-20.04.docker .
       popd

#### Build the Passport model Docker Image using Docker Compose

1. Install [Docker Compose](https://docs.docker.com/compose/install/).

2. Build the passport model image(s):

       docker-compose build --build-arg uid="$UID" --build-arg gid="$UID"

3. Run the passport model container:

       docker-compose run --rm charra-dev-env

<!-- TODO: Uncomment this when verified that it works
### Run passport model Apps in Docker Compose

    docker-compose run --rm -T charra-attester &
    docker-compose run --rm -T charra-verifier
-->

#### Build the Passport model Docker Image using Docker

1. Build passport model Docker image:

       ./docker/build.sh
       if there is an error: (docker build --no-cache .)

2. Run passport model Docker container:

       ./docker/run.sh

<!-- #### Compile and Run CHARRA

1. Compile  (inside container):

       cd charra/
       make -j

2. Run  (inside container):

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT attester

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D

 ### Compile and Run Manually 

The provided `Dockerfile` lets you quickly test CHARRA-PM in a Docker environment.
If you want to run passport model bare metal, please refer to this guide here.

#### Compile

The `Dockerfile` provides details on installing all dependencies and should be considered authoritative over this.

1. Install all dependencies that are needed for the [TPM2 TSS](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md).

2. Install *libcoap*:

       git clone --depth=1 --recursive -b 'develop' \
           'https://github.com/obgm/libcoap.git' /tmp/libcoap
       cd /tmp/libcoap
       ./autogen.sh
       ./configure --disable-tests --disable-documentation \
           --disable-manpages --disable-dtls --disable-shared \
           --enable-fast-install
       make -j
       make install

   Make sure that you do not have `libcoap-1-0-dev` installed, as the headers might conflict.

3. Install *mbedtls*:

       git clone --depth=1 --recursive -b 'development' \
           'https://github.com/ARMmbed/mbedtls.git' /tmp/mbedtls
       cd /tmp/mbedtls
       make -j lib SHARED=true
       make install

4. Install *QCBOR*:

       git clone --depth=1 --recursive -b 'master' \
           'https://github.com/laurencelundblade/QCBOR.git' /tmp/qcbor
       cd /tmp/qcbor
       make -j all so
       make install install_so

5. Install *t_cose*:

       git clone --depth=1 --recursive -b 'master' \
           'https://github.com/laurencelundblade/t_cose.git' /tmp/t_cose
       cd /tmp/t_cose
       make -j -f Makefile.psa libt_cose.a libt_cose.so
       make -f Makefile.psa install install_so

6. Compile programs:

       make -j

#### Further Preparation

1. Download and install [IBM's TPM 2.0 Simulator](https://sourceforge.net/projects/ibmswtpm2/).

2. Download and install the [TPM2 Tools](https://github.com/tpm2-software/tpm2-tools).

#### Run

1. Start the TPM Simulator (and remove the state file `NVChip`):

       (cd /tmp ; pkill tpm_server ; rm -f NVChip; /usr/local/bin/tpm_server > /dev/null &)

2. Send TPM *startup* command:

       /usr/local/bin/tpm2_startup -Tmssim --clear

3. Run Attester and Verifier:

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D

## Debugging

* Clang `scan-build`:

      make clean ; scan-build make

* Valgrind:

      (valgrind --leak-check=full \
          --show-leak-kinds=all -v \
          bin/attester \
          2> attester-valgrind-stderr.log &); \
      sleep .2 ; \
      (valgrind --leak-check=full \
          --show-leak-kinds=all -v \
          bin/verifier\
          2> verifier-valgrind-stderr.log) ;\
      sleep 1 ; \
      pkill -SIGINT -f bin/attester

* AddressSanitizer:

      make clean ; make address-sanitizer=1
      (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester

  This Make flag is part of the CHARRA `Makefile` and adds the `-fsanitize=address` argument to `CFLAGS` and `LDFLAGS`.
-->

## Run Attester and Verifier on different Devices

The attester and verifier can be used on two different devices.
To do that, you have to provide an external network for the attester Docker container.

1. Create [macvlan network](https://docs.docker.com/network/macvlan/) for attester Docker container (check your gateway address and replace `x` with the correct number):

       docker network create -d macvlan \
           --subnet=192.168.x.0/24 \
           --gateway=192.168.x.1 \
           -o parent=eth0 pub_net

2. Add `--network` parameter to the `docker run` command in the `docker/run.sh` on the attester device:

       ## run (transient) Docker container
       /usr/bin/docker run --rm -it \
           -v "${PWD}/:/home/bob/charra" \
           --network=pub_net \
           "${docker_image_fullname}" \
           "$@"

3. Run the attester Docker container and check the IP address.
       docker container inspect e2413b09d4dc | grep IPAddress


4. Put the attester address to the `DST_HOST` in `src/verifier.c` on the verifier device.
   Rebuild verifier script in the verifier docker container:

       cd charra
       make -j

5. Go to `charra` directory and run attester binary in the attester docker container:

       cd charra
       bin/attester -r --ip-rp=192.168.0.3 # ip of the verifier

6. Run the relying_party binary in the relying party docker container (This must be up before verifier runs):

       /bin/relying_party -r

6. Run the verifier binary in the verifier docker container:

       /bin/verifier -r --ip=192.168.0.2

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D

For more parameter details, run one of the binary with `-h` parameter.

#### My notes

```
  git clone https://github.com/sbabic/swupdate.git -b 2023.05 && cd swupdate: 
   ls configs/ -1
   make test_defconfig
   make menuconfig
   make 
   sudo make install

   openssl genrsa -out swupdate-priv.pem
   openssl rsa -in swupdate-priv.pem -out swupdate-public.pem -outform PEM -pubout
   sudo swupdate -v -k /home/ab/swupdate/swupdate-public.pem -w "--document-root /home/ab/swupdate/web-app --port 8080"
```





   https://mkrak.org/2018/01/26/updating-embedded-linux-devices-part2/

   





## Disclaimer

RASUES is an  early release that could contain issues and inconsistencies. The implementations provided in this repository are currently only research prototypes.
