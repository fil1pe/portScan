# portScan

portScan lists the remote IP addresses and ports being used by TCP and UDP applications. Its implementation follows SNMP version 2c.

## Before installation

You must have installed ``snmp`` on the manager machine as

```console
$ sudo apt install snmp
```

and ``snmpd`` on the agent devices:

```console
$ sudo apt install snmpd
```

For your SNMP agent, make sure you have set a read-only community in /etc/snmp/snmpd.conf like this:

``
rocommunity public
``

Finally, install the developer package for Net-SNMP on the manager machine:

```console
$ sudo apt install libsnmp-dev
```

## Installation

In order to install portScan in your current directory, just run

```console
$ make community=public
```

replacing ``public`` by the SNMP agent read-only community you want.

To include the binary file in the primary directory of the system, do

```console
$ sudo make install community=public
```

## Usage

To list the established TCP connections on some agent host ``x.x.x.x``, run

```console
$ portScan x.x.x.x -TCP
```

and for UDP:

```console
$ portScan x.x.x.x -UDP
```

You can obtain the remote IP addresses and ports for both protocols this way:

```console
$ portScan x.x.x.x
```