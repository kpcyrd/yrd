yrd
===

cjdns for humans and cyborgs

    < kpcyrd> I resolved one of my major problems with cjdns
    < kpcyrd> systemd logged cjdns output with 'sh' as program name. Now it's yrd

How to install cjdns with yrd
-----------------------------

If you're running arch, checkout the [package](https://aur.archlinux.org/packages/yrd/) prurigro built for arch.

    git clone https://github.com/kpcyrd/yrd.git
    cd yrd
    # install dependencies
    apt-get install python-argh python-requests
    # install yrd
    ./install.py
    # if you're using systemd
    cp init/yrd.service /etc/systemd/system/
    systemctl enable yrd
    systemctl start yrd
    # if you're using init-sysv
    cp init/yrd.sh /etc/init.d/yrd
    update-rc.d yrd enable
    service yrd start

Sample Output
-------------

### Shows infos about your node
```
$ yrd addr
addr            fc29:09c3:74d3:6ce0:3381:90f6:4e05:a5e8
key             92dyb2331kd5txjucrgwv98zq88rvcf5nnzzknu66sr7vr3pwum0.k
version         v13

links           3
known routes    130
```

### Show your neighbors (peerStats)
```
$ yrd n
fcc7:f439:fe7e:2c87:8bc9:caee:87a7:79ec 0000.0000.0000.0015  v13  13465394 8787880   ESTABLISHED  0/563/0
fc4b:2571:aa1a:d4d1:67d6:2d57:c2d2:a329 0000.0000.0000.1935  v13         0   49160  UNRESPONSIVE  0/0/0
```

### Show your neighbors and their neighbors
```
$ yrd n -n
fcc7:f439:fe7e:2c87:8bc9:caee:87a7:79ec 0000.0000.0000.0015  v13  13483150 8798940   ESTABLISHED  0/563/0
   fc9b:6269:cbae:3e26:31e1:8f68:8cea:337b   0000.05f7.ba69.3555  v13
   fcee:8f6d:f866:da17:364f:4ade:08f7:3248   0000.0000.bbab.3555  v13
   fcc8:834d:f4e5:77e6:1415:81e7:bd0b:e1c0   0000.0000.0000.0135  v13
fc4b:2571:aa1a:d4d1:67d6:2d57:c2d2:a329 0000.0000.0000.1935  v13         0   49200  UNRESPONSIVE  0/0/0
   fcc8:834d:f4e5:77e6:1415:81e7:bd0b:e1c0   0000.0000.0000.0135  v13
   fc42:0af2:018d:3505:7506:d730:49ae:2ffa   0000.0000.000a.e935  v13
   fccd:390e:90fb:e785:f26b:18dd:6344:d182   0000.0000.000a.6935  v13
```
### Utilize Nightfall
[Nightfall](https://github.com/kpcyrd/nightfall) is a cjdns inet auto-peering tracker.

```
$ ./yrd.py nf get http://nf.rxv.cc:7473/promisc/seek/
```

### Show bandwidth
```
$ yrd n -b
fce0:cc9d:a435:2247:1b61:9dc5:1ef1:dd83 0000.0000.0000.0015  v15     3 Kb/s    2 Kb/s   ESTABLISHED  0/11/0  'Local Peers'
fc56:2edc:3842:ff64:b57a:dc03:ce9c:fa36 0000.0000.0000.0013  v15    580 B/s   948 B/s   ESTABLISHED  0/7/0  'Local Peers'
```

### Ping a node (5 times)
```
$ yrd ping fc42:0af2:018d:3505:7506:d730:49ae:2ffa -c 5
Reply from fc42:0af2:018d:3505:7506:d730:49ae:2ffa@0000.0000.000a.e935 105ms
Reply from fc42:0af2:018d:3505:7506:d730:49ae:2ffa@0000.0000.000a.e935 135ms
Reply from fc42:0af2:018d:3505:7506:d730:49ae:2ffa@0000.0000.000a.e935 113ms
Reply from fc42:0af2:018d:3505:7506:d730:49ae:2ffa@0000.0000.000a.e935 96ms
Reply from fc42:0af2:018d:3505:7506:d730:49ae:2ffa@0000.0000.000a.e935 164ms
```

### Dump nodestore (first 3 entries)
```
$ yrd r | head -3
fc49:4bb0:30f4:5ea5:0eaa:1484:7d37:68ef 0000.0000.6779.a935  v13    17782483   45415
fc90:8d45:cb0e:48b7:0bc1:60f8:4215:36cf 0000.0004.d339.a935  v13    14307405   82707
fcd1:ea5d:24e5:cc7a:0ada:8d93:ebf7:22b7 0000.0000.0531.a935  v13    12322684   31373
```

### Count nodestore
```
$ yrd r | wc -l
130
```

### Show uplinks of a node
```
$ yrd uplinks fc42:0af2:018d:3505:7506:d730:49ae:2ffa
fc48:6c0f:a8ab:c0b1:1f2c:5de7:378d:9da6   0000.0000.000a.2935  v13
fc4b:2571:aa1a:d4d1:67d6:2d57:c2d2:a329   0000.0000.0000.1935  v13
-
```

### Whois lookup
Asks the remote server for whois information.

The remote server needs to run a whoisd like [iam](https://github.com/kpcyrd/iam).

```
# yrd whois fc42:0af2:018d:3505:7506:d730:49ae:2ffa
% Hyperboria Whois Information
%
foobar
```

How to pronounce this
---------------------

Like "wired"

"Thanks" goes to
----------------

- appa - found some bugs and rough edges
- prurigro - testing and building arch packages

Contributing
------------

1. Clone this repo
2. Do your changes
3. Run `./check.sh` to check if your changes are ok
4. Open a pull request

License
-------

GPLv3

