#!/usr/bin/env python3
#File   : cf-report.py: A script to display CF vents
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
parser.add_argument('--twohour', help="Display two hour report ", action="store_true")
parser.add_argument('--interval', help="Where applicable use this interval ", action="store", default=120)
parser.add_argument('--stacked', help="Display a stacked bar of alert types ", action="store_true")
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
    
def createGraphAll():
    #create line  Graph of all events
    events=[]
    times=[]
    query="select id, timestamp, (total-log) from events where zone like ? order by id desc limit 120" 
    results=queryAllRowsVar(query,args.zonename)
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
    plt.title(args.zonename + " Cloudflare Events last two hours")
    plt.xlabel("Date") 
    plt.ylabel("Events")
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
    plt.show()

     

if not path.exists(args.db):
    print("DB File not found, exiting")
    quit()

else: 
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

if args.twohour:
    createGraphAll()

if args.stacked:
    createStackedBar()
