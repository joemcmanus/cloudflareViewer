#!/usr/bin/env python3
#File   : cf-details.py: This script stores details Cloudflare firewall events in a sqlite db for better analysis
#Author : Joe McManus josephmc@alumni.cmu.edu
#Version: 0.1 2022/05/30

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


#Notes on using Cloudflare's API: 
#https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events


from prettytable import PrettyTable
import argparse
import json
from datetime import datetime, timedelta
import sys
import requests
import sqlite3
from collections import Counter
from os import path 
import pprint


parser = argparse.ArgumentParser(description='Cloudflare FW Event Exporter')
parser.add_argument('--token', help="CF API Token", action="store")
parser.add_argument('--zoneid', help="CF Zone ID", action="store")
parser.add_argument('--zonename', help="CF Zone ID", action="store", default=None)
parser.add_argument('--db', help="SQLite DB file, defaults to cf-details.sql3 if not provided.  requires.", action="store", default='cf-details.sql3')
args=parser.parse_args()

if not args.token:
    print("ERROR: Must provide --token ")
    quit()

if not args.zoneid:
    print("ERROR: Must provide --zoneid")
    quit()

def getResults(url, headers, data):
    r = requests.post(url, headers=headers, data=data.replace('\n', ''))
    return r.json()

def queryOneRow(query):
    cursor=db.cursor()
    cursor.execute(query)
    result=cursor.fetchone()
    return(result)

def queryAllRows(query):
    cursor=db.cursor()
    cursor.execute(query)
    result=cursor.fetchall()
    return(result)

def queryOneRowVar(query, var):
    t=(var,)
    cursor=db.cursor()
    cursor.execute(query,t)
    result=cursor.fetchone()
    return(result)

def queryAllRowsVar(query,var):
    cursor=db.cursor()
    t=(var,)
    cursor.execute(query,t)
    result=cursor.fetchall()
    return(result)

if path.exists(args.db):
    print("DB File Found")
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

#Create a DB if one does not exist
if not path.exists(args.db):
    print("DB File not found, creating")
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row
    query="""CREATE TABLE events (id INTEGER PRIMARY KEY,
        timestamp datetime NOT NULL,
        ja3Hash VARCHAR(256),
        clientIP VARCHAR(256),
        ruleId VARCHAR(256),
        userAgent VARCHAR(1024),
        botScore INT,
        action VARCHAR(256),
        zone VARCHAR(256)
        clientRequestHTTPHost VARCHAR(256),
        botScoreSrcName VARCHAR(256)
        )"""
    queryOneRow(query)


startDate= datetime.utcnow().replace(microsecond=0).isoformat()
endDate= (datetime.utcnow().replace(microsecond=0) - timedelta(minutes=5)).isoformat()

payload = f'''{{"query":
  "query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {{
    viewer {{
      zones(filter: {{ zoneTag: $zoneTag }}) {{
        firewallEventsAdaptive(
          filter: $filter
          limit: 10000
          orderBy: [datetime_DESC]
        ) {{
          action
          clientIP
          botScore
          ja3Hash
          userAgent
          ruleId
          datetime
          clientRequestHTTPHost
          botScoreSrcName
        }}
      }}
    }}
  }}",
  "variables": {{
    "zoneTag": "{args.zoneid}",
    "filter": {{ 
      "datetime_geq": "{endDate}Z",
      "datetime_leq": "{startDate}Z"
    }}
  }}
}}'''
headers = {'Authorization': "Bearer " + args.token, "content-type": "application/json"}
url="https://api.cloudflare.com/client/v4/graphql/"

#Get the events from Cloudflare
events=getResults(url, headers, payload)

pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(events)
#quit()

actions=0

for x in events["data"]["viewer"]["zones"]:
    for y in x.items():
        for z in y[1]:
            #pp.pprint(z)
            t=(z['action'], z['clientIP'], z['botScore'], z['ja3Hash'], z['userAgent'],z['ruleId'], z['datetime'], z['clientRequestHTTPHost'], z['botScoreSrcName'], args.zonename)
            query='insert into events(action, clientIP, botScore, ja3Hash,  userAgent, ruleId, timestamp, clientRequestHTTPHost, botScoreSrcName, zone) values(?,?,?,?,?,?,?,?,?,?)'
            cursor=db.cursor()
            cursor.execute(query, t)

db.commit()

