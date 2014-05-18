#!/usr/bin/env python
# encoding: utf-8

import ctypes
import struct
from socket import inet_ntoa
from socket import gethostbyaddr

class Truncated_Error(Exception):
    def __init__(self, f):
        self.f = f
    def __str__(self):
        print "File %s seems to be truncated after %d Bytes"\
                     % (self.f.name, self.f.tell())

SIZEOF_INT = 4 # 4bytes = 32bit # ctypes.sizeof(ctypes.c_int)
SIZEOF_FLOAT = 4 # 4 Bytes = 32bit # ctypes.sizeof(ctypes.c_float)
BLOCK_HEADER = "<iiii" # cId, uId, record_size, len
RECORD_HEADER = "<4si" # dstip, hops
TRACE_HEADER = "<4sfi" # hopped_ip, lat, ttl

# in_addr構造体は多分32bit

class IPlaneTraceFile(file):
    """
    このクラスは http://iplane.cs.washington.edu/data/data.html
    にある、traceroute経路情報をピュアPythonでパースし、
    2重にイテレートできるようにするものです。
    Usage
    ===========
    f = IPlaneTraceFile("trace.out.planetlab1.dojima.wide.ad.jp", src="planetlab1.dojima.wide.ad.jp")
    for record in f:
        for dstip, hops, traceIter in record:
            path_to_dstip = dstip
            for hopped_ip, lat, ttl in traceIter:
                path_to_dstip = path_to_dstip + "=>" + hopped_ip
            print path_to_dstip
    ===========
    """

    def __init__(self, fname, src=None):
        file.__init__(self, fname)
        self.block = 0
        self.count = 0
        if src is None: #srcを省略した場合はファイル名をsrcにする。
            self.src = fname
        else:
            self.src = src
        self.record_size = 0

    def __iter__(self):
        return self

    def _readBlock(self):
        try:
            return struct.unpack(BLOCK_HEADER, self.read(4*SIZEOF_INT) )
            #return cId, uId, record_size, length
        except Exception as e:
            print e
            raise Truncated_Error(self)

    def _readRecord(self):
        try:
            return struct.unpack(RECORD_HEADER, self.read(2*SIZEOF_INT))
            #return dstip, hops
        except Exception as e:
            print e
            raise Truncated_Error(self)

    def _readTrace(self):
        try:
            return struct.unpack(
                TRACE_HEADER, self.read(
                    SIZEOF_INT + SIZEOF_FLOAT + SIZEOF_INT
                )
            )
            #return hopped_ip, lat, ttl
        except Exception as e:
            print e
            raise Truncated_Error(self)

    def next(self):
        if self.count >= self.record_size: #1ブロックの全レコードを読み終えた
            if self.read(1) != "":#次のデータがあるかどうかチェック
                #まだあるなら次のブロックを読み込み
                self.seek(self.tell()-1)
                self.cId, self.uId, self.record_size, self.length = self._readBlock()
                self.count = 0
            else:#次のデータが無いならイテレートを停止。
                raise StopIteration
            self.block = self.block + 1
        def record_iter():
            self.count = self.count + 1
            dstip, hops = self._readRecord()
            def trace_iter():
                for i in range(hops):
                    hopped_ip, lat, ttl = self._readTrace()
                    if ttl > 512:
                        raise Truncated_Error(self)
                    yield (inet_ntoa(hopped_ip), lat, ttl)
            yield (inet_ntoa(dstip), hops, trace_iter())
        records = record_iter()
        return records

    def __del__(self):
        if not self.closed:
            try:
                self.close()
            except:
                pass

dnscache = {}
def resolvIP(ip):
    try:
        if ip in dnscache:
            return dnscache[ip]
        host = gethostbyaddr(ip)[0]
        dnscache.update({ip:host})
        return host
    except:
        return ip

ascache = {}
try:
    from scapy.as_resolvers import AS_resolver_multi
    asr=AS_resolver_multi()
    def resolvAS(ip):
        try:
            if ip in ascache:
                return ascache[ip]
            else:
                AS = asr.resolve(ip)[0][2]
                ascache.update({ip:AS})
                return AS
        except Exception as e:
            print e
            return ip
except Exception as e:
    print e
    resolvAS = lambda ip:ip

if __name__ == "__main__":
    resolv = True
    f = IPlaneTraceFile("trace.out.planetlab1.dojima.wide.ad.jp",src="planetlab1.dojima.wide.ad.jp") # wget http://iplane.cs.washington.edu/data/today/traces/count.out.planetlab1.dojima.wide.ad.jp
    for record in f:
        print "cId=%d,uId=%d,record=%d,len=%d" % \
            (f.cId,f.uId,f.record_size,f.length)
        for dstip, hops, traceIter in record:
            print "Destination: %s\tTotal Hops: %d" % (dstip, hops)
            i=0
            print
            print ">",f.src
            for hopped_ip, lat, ttl in traceIter:
                i+=1
                if ttl == 0:
                    hopped_ip = "===UNKNOWN==="
                if resolv:
                    AS = resolvAS(hopped_ip)
                    hopped_ip = resolvIP(hopped_ip)
                    print "-"*i+">","\t%s\tLatency: %f\t%s" % \
                        (hopped_ip, lat, AS)
                else:
                    print "-"*i+">","\t%s\tLatency: %f" % \
                        (hopped_ip, lat)
            raw_input("Type Enter ... (next record)")
    exit(0)
#    for record in f:
#        for dstip, hops, traceIter in record:
#            path_to_dstip = dstip
#            for hopped_ip, lat, ttl in traceIter:
#                path_to_dstip = path_to_dstip + "=>" + hopped_ip
#            print path_to_dstip
#    exit(0)
