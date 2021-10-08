#!/usr/bin/env python3

import json;

pops = [];

with open('table.csv', 'r') as csvfile: 
    next(csvfile);
    for row in csvfile.readlines():
        d = {};
        [network, country, address, subnet, radius] = row.split(";")
        d["ip"] = subnet
        d["pop"] = address
        d["radius"] = int(radius.replace("\n",""))
        d["country"] = country         
        pops.append(d)

with open('locations.json', 'w') as locations: 
    j = {"pops": pops}
    json.dump(j, locations, indent=4)
