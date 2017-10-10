from .xcjdns import addr2ip, collect_from_address

def test_addr2ip():
    addrs = [
        ('v20.0000.0000.0000.0017.c5bu0npp8by4jym96mh0vyy81sn9lhbc01f445nvz64dvdjt98j0.k',
            'fc72:e647:378a:35b6:c343:da8f:db16:3f92'),
        ('v0.0000.0000.0000.0015.1nctdb89gtfrlnu71zyq97n14frl1r4z0ylwzc8vn7kpvrzu4yl0.k',
            'fc00:0000:28a7:1600:168d:4349:4d28:ba73'),
    ]

    for addr, expected in addrs:
        print('trying %r' % addr)
        ip = addr2ip(addr)
        print('got %r' % ip)
        assert ip == expected


def test_collect_from_address():
    addrs = [
        ('v20.0000.0000.0000.0017.c5bu0npp8by4jym96mh0vyy81sn9lhbc01f445nvz64dvdjt98j0.k', {
            'path': 'v20.0000.0000.0000.0017.c5bu0npp8by4jym96mh0vyy81sn9lhbc01f445nvz64dvdjt98j0.k',
            'key': 'c5bu0npp8by4jym96mh0vyy81sn9lhbc01f445nvz64dvdjt98j0.k',
            'ip': 'fc72:e647:378a:35b6:c343:da8f:db16:3f92'}),
        ('v0.0000.0000.0000.0015.1nctdb89gtfrlnu71zyq97n14frl1r4z0ylwzc8vn7kpvrzu4yl0.k', {
            'path': 'v0.0000.0000.0000.0015.1nctdb89gtfrlnu71zyq97n14frl1r4z0ylwzc8vn7kpvrzu4yl0.k',
            'key': '1nctdb89gtfrlnu71zyq97n14frl1r4z0ylwzc8vn7kpvrzu4yl0.k',
            'ip': 'fc00:0000:28a7:1600:168d:4349:4d28:ba73'}),
    ]

    for addr, expected in addrs:
        print('trying %r' % addr)
        stuff = collect_from_address(addr)
        print('got %r' % stuff)
        assert stuff == expected
