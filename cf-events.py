#!/usr/bin/env python3
#File   : cf-events.py: A script to display CF vents
#Author : Joe McManus josephmc@alumni.cmu.edu
#Version: 0.1 2022/05/15

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


parser = argparse.ArgumentParser(description='Cloudflare FW Event Exporter')
parser.add_argument('--token', help="CF API Token", action="store")
parser.add_argument('--zone', help="CF Zone ID", action="store")
parser.add_argument('--db', help="SQLite DB file, defaults to cf-events.sql3 if not provided.  requires.", action="store", default='cf-events.sql3')
args=parser.parse_args()

if not args.token:
    print("ERROR: Must provide --token ")
    quit()

if not args.zone:
    print("ERROR: Must provide --zone")
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
        managed_challenge INT,
        log INT,
        allow INT,
        managed_challenge_bypassed INT,
        challenge INT,
        challenge_bypassed INT,
        block INT,
        managed_challenge_non_interactive_solved INT,
        jschallenge_bypassed INT,
        jschallenge INT,
        challenge_solved INT,
        managed_challenge_interactive_solved INT,
        jschallenge_solved INT
        )"""
    queryOneRow(query)


startDate= datetime.utcnow().replace(microsecond=0).isoformat()
endDate= (datetime.utcnow().replace(microsecond=0) - timedelta(minutes=1)).isoformat()

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
        }}
      }}
    }}
  }}",
  "variables": {{
    "zoneTag": "{args.zone}",
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

actions=0
actionTypes=[]

for x in events["data"]["viewer"]["zones"]:
    for y in x.items():
        for z in y[1]:
            actions+=1
            actionTypes.append(z['action'])
            
cnt=Counter()
for action in actionTypes:
    cnt[action] += 1


#create a new empty report
query='insert into events(timestamp) values(datetime())'
queryOneRow(query)

#get report id
query='SELECT id,timestamp FROM events ORDER BY timestamp DESC LIMIT 1'
reportID,timestamp=queryOneRow(query)


for action, count in cnt.most_common():
    t=(count, reportID)
    query="UPDATE events SET " + action +"  = ? WHERE id = ?"
    cursor=db.cursor()
    cursor.execute(query, t)
    db.commit()

