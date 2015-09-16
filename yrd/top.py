grey = '\x1b[30m'
red = '\x1b[31m'
green = '\x1b[32m'
yellow = '\x1b[33m'
reset = '\x1b[0m'

clear = '\x1b[2J\x1b[H'


class Session(object):
    def __init__(self):
        self.store = {}

    def update(self, line):
        addr = line[:39]
        path = line[40:59]

        try:
            return self.store[addr].update(path)
        except KeyError:
            self.store[addr] = Node(path)

    def fmt(self, line, signal):
        addr = line[:39]
        n = self.store[addr]
        return line[:40] + n.fmt(signal) + line[59:]

    def output(self, neighbours, lines, n):
        neighbours = [x[:39] + ' ' + Node(x[40:59]).fmt() + ' ' + x[60:64] for x in neighbours]

        buf = list(lines)
        buf.sort(key=lambda x: x[40:59], reverse=True)
        buf = [self.fmt(line, self.update(line)) for line in buf]

        output = clear

        if neighbours:
            output += '\n'.join(neighbours) + '\n\nNodestore (%d):\n' % len(buf)

        output += '\n'.join(buf[:n])

        return output


def cmp(a, b):
    return (a > b) - (a < b)


class Node(object):
    def __init__(self, path):
        self.path = path
        self.dist = self.calc(path)

    def update(self, path):
        if path != self.path:
            self.path = path
            o = self.dist
            self.dist = self.calc(path)
            return cmp(o, self.dist)

    def calc(self, path):
        return len(path.lstrip('0.'))

    def fmt(self, signal=None):
        cut = 19-self.dist
        c = reset if signal is None else green if signal > 0 else red if signal < 0 else yellow
        return grey + self.path[:cut] + c + self.path[cut:] + reset
