#!/usr/bin/env python3
#File   : cf-report.py: A script to display CF vents
#Author : Joe McManus josephmc@alumni.cmu.edu
#Version: 0.2 2022/05/30

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

import sqlite3
import datetime
import argparse
import sys
from prettytable import PrettyTable
from os import path
import plotext as plt
import pandas as pd




parser = argparse.ArgumentParser(description='Cloudflare FW Event Exporter')
parser.add_argument('--db', help="SQLite DB file, defaults to cf-events.sql3 if not provided.  requires.", action="store", default='cf-events.sql3')
parser.add_argument('--events', help="Display all events in a line graph", action="store_true")
parser.add_argument('--interval', help="Where applicable use this interval ", action="store", default=120)
parser.add_argument('--stacked', help="Display a stacked bar of alert types ", action="store_true")
parser.add_argument('--ja3', help="Display a table of ja3 hashes ", action="store_true")
parser.add_argument('--zonename', help="Limit to a named zone, default=all ", action="store", default="%")

args=parser.parse_args()

if len(sys.argv) == 1: 
    parser.print_help()
    sys.exit()

def makeFilename(title):
    #first remove spaces
    title=title.replace(" ","-")
    #next remove slashes
    title=title.replace("/","")
    #return the title with .html on the end so we don't get alerts
    title=args.outdir + "/" + title + ".png"
    return title

def queryOneRow(query):
    cursor=db.cursor()
    cursor.execute(query)
    result=cursor.fetchone()
    return(result)

def queryOneRowVar(query, var):
    t=(var,)
    cursor=db.cursor()
    cursor.execute(query,t)
    result=cursor.fetchone()
    return(result)

def queryAllRows(query):
    cursor=db.cursor()
    cursor.execute(query)
    result=cursor.fetchall()
    return(result)
    
def queryAllRowsVar(query,var):
    cursor=db.cursor()
    t=(var,)
    cursor.execute(query,t)
    result=cursor.fetchall()
    return(result)

def ja3Table():
    ja3Hashes=[]
    hashCount=[]
    userAgents=[]
    t=(args.zonename, )
    table= PrettyTable(["JA3", "Count", "User Agents"])
    query="select distinct(ja3Hash) as hash, count(ja3Hash) as occur, count(distinct(userAgent))  from events where action != 'allow' and botScoreSrcName != 'Verified Bot' and zone=? and ja3Hash != '' group by hash order by occur desc  limit 20 "
    cursor=db.cursor()
    cursor.execute(query, t)
    results=cursor.fetchall()
    for row in results:
        ja3Hashes.append(row[0][0:6])
        hashCount.append(row[1])
        userAgents.append(row[2])
        table.add_row([row[0], row[1], row[2]])

    print(table)

    plt.bar(ja3Hashes, hashCount)
    plt.title("JA3 Hash Occurences")
    plt.show()



def createGraphAll():
    #create line  Graph of all events
    events=[]
    times=[]

    t=(args.zonename, args.interval,)
    #query='select id, timestamp, (total-log) from events where zone like ? and timestamp > datetime(\'now\', \'-? minutes\') order by id desc'
    query='select id, timestamp, (total-log) from events where zone like ?  order by id desc limit ?'
    cursor=db.cursor()
    cursor.execute(query, [args.zonename, args.interval])
    results=cursor.fetchall()
    for row in results:
        times.append(row[1])
        events.append(row[2])

    #reverse the lists so they can print correctly
    times.reverse()
    events.reverse()

    plt.date_form('Y-m-d H:M:S')
    start=times[0]
    end=times[-1]

    plt.plot(times, events)
    plt.title(args.zonename + " Cloudflare Events")
    plt.xlabel("Date") 
    plt.ylabel("Events")
    #plt.canvas_color("black")
    plt.show()

def toZero(value):
    if value == None:
        return 0
    else:
        return value

def createStackedBar():
    timestamp =[]
    managed_challenge =[]
    log =[]
    allow =[]
    managed_challenge_bypassed =[]
    challenge =[]
    challenge_bypassed =[]
    block =[]
    managed_challenge_non_interactive_solved =[]
    jschallenge_bypassed =[]
    jschallenge =[]
    challenge_solved =[]
    managed_challenge_interactive_solved =[]
    jschallenge_solved = []
   
    t=(args.zonename, args.interval)
    query="select * from events where zone like %s and timestamp >  datetime('now', '-%i minutes') order by id desc"
    query="select * from events where zone like ? order by id desc limit ?"
    cursor=db.cursor()
    cursor.execute(query, t)
    results=cursor.fetchall()
    for row in results:
        timestamp.append(toZero(row[1]))
        managed_challenge.append(toZero(row[2]))
        log.append(toZero(row[3]))
        allow.append(toZero(row[4]))
        managed_challenge_bypassed.append(toZero(row[5]))
        challenge.append(toZero(row[6]))
        challenge_bypassed.append(toZero(row[7]))
        block.append(toZero(row[8]))
        managed_challenge_non_interactive_solved.append(toZero(row[9]))
        jschallenge_bypassed.append(toZero(row[10]))
        jschallenge.append(toZero(row[11]))
        challenge_solved.append(toZero(row[12]))
        managed_challenge_interactive_solved.append(toZero(row[13]))
        jschallenge_solved.append(toZero(row[14]))

    timestamp.reverse()
    managed_challenge.reverse()
    log.reverse()
    allow.reverse()
    managed_challenge_bypassed.reverse()
    challenge.reverse()
    challenge_bypassed.reverse()
    block.reverse()
    managed_challenge_non_interactive_solved.reverse()
    jschallenge_bypassed.reverse()
    jschallenge.reverse()
    challenge_solved.reverse()
    managed_challenge_interactive_solved.reverse()
    jschallenge_solved.reverse()
   

    plt.stacked_bar(timestamp, 
        [managed_challenge, 
        managed_challenge_bypassed, 
        allow, 
        challenge, 
        challenge_bypassed, 
        block, 
        managed_challenge_non_interactive_solved, 
        jschallenge_bypassed,  
        jschallenge, 
        challenge_solved, 
        managed_challenge_interactive_solved, 
        jschallenge_solved],
        label=
        ["managed_challenge", 
        "managed_challenge_bypassed", 
        "allow", 
        "challenge", 
        "challenge_bypassed", 
        "block", 
        "managed_challenge_non_interactive_solved", 
        "jschallenge_bypassed",  
        "jschallenge", 
        "challenge_solved", 
        "managed_challenge_interactive_solved", 
        "jschallenge_solved"])
    plt.title(args.zonename + " Events")
    #plt.canvas_color("black")
    plt.show()

     

if not path.exists(args.db):
    print("DB File not found, exiting")
    quit()

else: 
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

if args.events:
    createGraphAll()

if args.stacked:
    createStackedBar()

if args.ja3:
    ja3Table()
