#!/usr/bin/env python
import redis
from tabulate import tabulate

r = redis.StrictRedis(host='127.0.0.1', port=6379, db=2)
keys = r.keys('BMTOR*')
headers = ['UNDERLAY DIP', 'OVERLAY DIP', 'VNI', 'OCTETS']
rows = []
for key in keys:
	rows.append([
            r.hget(key, 'UNDERLAY_DIP'),
            r.hget(key, 'OVERLAY_DIP'),
            r.hget(key, 'VNI'),
            r.hget(key, 'BYTES'),
            ])

print tabulate(rows, headers, tablefmt='grid')
