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

import sqlite3
import datetime
import argparse
import sys
from prettytable import PrettyTable
import plotly
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
from os import path
import plotext as plt




parser = argparse.ArgumentParser(description='Cloudflare FW Event Exporter')
parser.add_argument('--db', help="SQLite DB file, defaults to cf-events.sql3 if not provided.  requires.", action="store", default='cf-events.sql3')
parser.add_argument('--graphs', help="Display graphs where available", action="store_true")
parser.add_argument('--textgraphs', help="Display text graphs where available", action="store_true")

args=parser.parse_args()

if len(sys.argv) == 1: 
    parser.print_help()
    sys.exit()



def createGraph(yData, xData, yTitle, xTitle, title):
    plotly.io.write_image({
        "data":[ go.Bar( x=xData, y=yData) ],
        "layout": go.Layout(title=title,
            xaxis=dict(title=xTitle,type='category'),
            yaxis=dict(title=yTitle), )
        },makeFilename(title))


def createPieGraph(xData, yData, xTitle, yTitle, title, timestamp): 
    plotly.io.write_image({
        "data":[ go.Pie( labels=xData, values=yData, title=title + " " + timestamp)]},makeFilename(title))

def createStackedBar():
    cursor=db.cursor()
    df=pd.read_sql("select distinct(a.sev) as Severity, COUNT(DISTINCT(a.cve)) as Count, b.timestamp as date  from vulns a, reports b where a.reportID=b.reportID group by b.reportID, a.cve order by b.timestamp desc limit 20 ", db)
    title="Unique CVE"
    fig=px.bar(df, x="date", y="Count", color="Severity",title=title, color_discrete_sequence=px.colors.qualitative.D3)
    fig.update_layout(xaxis_type='category')
    fig.write_image(makeFilename(title))

    df=pd.read_sql("select distinct(a.sev) as Severity, COUNT(a.cve) as 'Machine Count',  b.timestamp as date  from vulns a, reports b where a.reportID=b.reportID group by b.reportID, a.cve", db)
    title="Hosts with CVEs"
    fig=px.line(df, x="date", y="Machine Count", color="Severity",title=title, color_discrete_sequence=px.colors.qualitative.D3)
    fig.write_image(makeFilename(title))

    df=pd.read_sql("select a.sev as Severity, a.sevCount as Count, b.timestamp as date from alerts a, reports b where a.reportID=b.reportID and sev <=2 and date >= date('now', '-14 days')", db)
    title="Alerts over Time"
    fig=px.line(df, x="date", y="Count", color="Severity",title=title, color_discrete_sequence=px.colors.qualitative.D3)
    fig.update_layout(xaxis_type='category')
    fig.write_image(makeFilename(title))


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
    query="select id, timestamp, (total-log) from events limit 120" 
    results=queryAllRows(query)
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
    plt.title("Cloudflare Events last two hours")
    plt.xlabel("Date") 
    plt.ylabel("Events")
    plt.show()

def createStackBar():

     timestamp datetime =[]
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

     query="select * from events limit 120"
     results=queryAllRows(query)
     for row in results:
        `

     

if not path.exists(args.db):
    print("DB File not found, exiting")
    quit()

else: 
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

if args.textgraphs:
    createGraphAll()
