"""An IPAddress Module.
"""

import pygeoip

wget_addr = 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz'

class IPAddress(object):
    def __init__(self):
        pyg = pygeoip.GeoIp('./geoip_databases/GeoLiteCity.dat')

    def approx_geograph(self, ip='', hostname=''):
        if self.ip:
            return self.pyg.record_by_addr(self.ip)
        elif self.hostname:
            return self.pyg.record_by_name(self.hostname)
        else:
            raise Exception('Undefined error')


def test_ip_address():
    """A function to test the ip_address object.
    """
    ipa = IPAddress(hostname='www.google.com')
    ipa.approx_geograph
    print ipa.record

if __name__ == '__main__':
    test_ip_address()

