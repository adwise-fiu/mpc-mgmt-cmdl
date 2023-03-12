# MPC Management Framework
MPC management framework automating a secure network setup among participants of multiparty computation in the outsourced setting.

We offer a comprehensive framework instantiating a proposed set of protocols for *participant registration* (i.e., client or server), *Kerberos-like authentication*, and *MPC job orchestration*. This framework suits the need of organizations that wants to set up their MPC system while temporarily incorporating computation power from other stakeholders or third parties.

<p align="center">
  <img src="https://github.com/ogbautista/mpc-mgmt-cmdl/blob/main/MPC_system_architecture.png" width="580">
</p>


## Table of Contents

1. [Python Dependencies](#python-dependencies)

2. [Running the Program](#running-the-program)

   2.1. [Registering Participants](#registering-participants)

   2.2. [Setting up the MPC Network](#setting-up-the-mpc-network)

   2.3. [Running on Different Hosts](#running-on-different-hosts)


## 1. Python Dependencies

### Installing Build Tools

Some of the dependencies require build tools installed in the system. This can be done as follows:

##### For linux systems

Debian-based systems:

```shell
sudo apt update
sudo apt install build-essential
```

RHEL-based systems:

```shell
sudo yum groupinstall "Development Tools"
```

##### For Windows systems

Required Microsoft Visual C++ 14.0 or greater. Get it with "Microsoft C++ Build Tools" (When using Python3.9)


### List of Dependencies
* msgpack
* cerberus
* pyDH
* pycryptodome
* ed25519
* scrypt
* twisted

Install the above python dependencies using `pip` (or `pip3` depending on your system). For instance, to install `msgpack` use
`pip3 install msgpack`

***Notes:***


1. During the installation of `ed25519` you may get an error related to `#include "Python.h"`. In such case, install the python3 header files depending on your system as follows.

Debian-based systems:
```shell
sudo apt-get install python3-dev
```
RHEL-based systems:
```shell
sudo yum install python3-devel
```

2. During the installation of `scrypt` you may get an error related to `#include <openssl/aes.h>`. In such case, install `openssl` depending on your linux system as follows.

Debian-based systems:
```shell
sudo apt-get install libssl-dev
```
RHEL-based systems:
```shell
sudo yum install openssl-devel
```
or for OS X with brew:
```shell
$ brew install openssl
$ export CFLAGS="-I$(brew --prefix openssl)/include $CFLAGS"
$ export LDFLAGS="-L$(brew --prefix openssl)/lib $LDFLAGS"
```

## 2. Running the Program

Run the MPC management server and participant programs as a Python module. Navigate to the project's base directory, then type:

##### The Management Server

```shell
python3 -m mpcframework.tmanager
```

##### An MPC Server

```shell
python3 -m mpcframework.mpcs
```

#### A (Source or Consumer) Client

```shell
python3 -m mpcframework.client
```

### 2.1. Registering Participants

First, run the MPC management server.

When trying to run a participant (MPC server or client) for the first time, or when trying to run a non-existent participant by specifying the participant Id, the program will prompt you to register a new identity:

```
python3 -m mpcframework.mpcs 4
» no information found for this mpc server id. register new mpcs? [yes]:
```

To proceed with the registration, type `yes` or press ENTER to confirm the default. Otherwise type `n` to exit.

In the case of a non-existing client, it will provide the user with an application command prompt. To register, type `register` and press ENTER, otherwise type `exit`.

```
python3 -m mpcframework.client 5
> register
```

If the client is registered as a consumer client, the program will provide another command prompt after a successful registration and subsequent authentication. Otherwise, as a data source client, the program will wait for commands from the MPC management server.

To register a client as a (data) consumer client, prior to running the program, go to the file `./mpcframework/network/client/client_registration_protocol.py` and change the value of the variable `iotype` from `input` to `output`, meaning that this client should receive the output of a secure computation.


### 2.2. Setting Up the MPC Network

Once there are enough MPC servers, at least one source client and at least one consumer client authenticated with the MPC management server, the system is ready to receive requests for a secure computation from a consumer client.

To run and authenticate a client with the MPC management server, simply run it indicating their `id` number as a parameter. When there is just one MPC server or client registered in a host, the `id` can be omitted.

On the consumer client console, type `register` and press ENTER.

```
analytics001> runmpc
```

This will trigger the automated MPC network setup. You can see the outcome of the execution on the MPC management server's console.

Note that this program sets up the MPC network between MPC servers and clients. The actual MPC protocol execution would require adding the corresponding MPC protocol to the MPC servers and integrating it with the `MpcControlProtocol` class.


### 2.3. Running on Different Hosts

The following configurations need to be considered when deploying the MPC management framework on different hosts:


#### Firewall rules

The MPC management server and the MPC servers open TCP ports to accept connection requests from other nodes. The corresponding allow rules need to be added to the firewalls as required.

The following TCP ports are used by default:

##### TCP Ports Opened by the MPC Management Server

* Registration server port: 1250
* Management server port: 1251

Configuration found in `./mpcframework/tmnetwork/`, files `regs_protocol.py` and `mgmt_protocol.py`

##### TCP Port Opened by an MPC Server

* TCP port for data input: 1270
* TCP port for reporting results: 1260

Configuration foun in `./mpcframework/network/mpcs/mpc_control_protocol.py`


#### MPC Management Server

The only server IP address participants need to know is the MPC management server IP, which also carries out the participant registration. The IP address specification is done in files located at `./mpcframework/network/` as follows:

* To contact the registration server, replace `'localhost'` for the corresponding MPC management server IP in line 13 of `network_protocol_base.py`

* To contact the MPC management server for the automated setup and other functionalities, replace `'localhost'` by the corresponding MPC management server IP address in line 15 of `authentication_protocol.py`
