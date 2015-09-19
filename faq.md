## How to install the service on sysv init?

```sh
cp init/yrd.sh /etc/init.d/yrd
update-rc.d yrd enable
service yrd start
```
