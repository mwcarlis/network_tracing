"""An IPAddress Module.
"""

import pygeoip
import geopy
from geopy import Nominatim


def singleton(cls):
    """A singleton decorator.
    """
    instances = {}
    def getinstance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return getinstance


wget_addr = 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz'

#@singleton
class IPAddress(object):
    def __init__(self):
        self.pyg = pygeoip.GeoIP('./geoip_databases/GeoLiteCity.dat')
        self.geolocator = Nominatim()

    def approx_geograph(self, ip='', hostname=''):
        if ip:
            return self.pyg.record_by_addr(ip)
        elif hostname:
            return self.pyg.record_by_name(hostname)
        else:
            raise Exception('Undefined error')

@singleton
class GeoIp(object):
    def __init__(self):
        pass

    def distance(self, record_a, record_b):
        if not ('latitude' in record_a and 'longitude' in record_a):
            raise Exception('latitude/longitude not in {}'.format(record_a))
        if not ('latitude' in record_b and 'longitude' in record_b):
            raise Exception('latitude/longitude not in {}'.format(record_b))
        point_a = ( record_a['latitude'], record_a['longitude'] )
        point_b = ( record_b['latitude'], record_b['longitude'] )
        return geopy.distance.vicenty(point_a, point_b).miles


def test_ip_address():
    """A function to test the ip_address object.
    """
    ipa = IPAddress()
    record = ipa.approx_geograph(hostname='www.google.com')
    return record

if __name__ == '__main__':
    import prettyprint
    prettyprint.pp(test_ip_address())

