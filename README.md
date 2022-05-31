# cloudflareViewer
A repo of tools to view Cloudflare API data

Are you a Cloudflare WAF customer? Do you need more from the data than the web page provides? Well I did :) 

This repo uses the Cloudflare API to download data about firewall events and stores it in a sqlite DB. Using Plotext it then creates graphs. 

Hopefully you'll find it useful. I'll be adding new graphs as I need them. 

# Usage

To download data you will need to have an API key and the Zone ID for your Cloudflare environment. Pass these to the program cf-events.py 

    #./cf-events.py  --token=ABC1234  --zoneid=DEF456 

To generate graphs use the command cf-report.py 

    #./cf-report.py --stacked 
    #./cf-report.py --twohour

You can add the option of --interval to specify the time range to query in minutes

    #./cf-report.py --stacked --interval=5 

Do you have multiple zones? You can specify which zone during the storage an retrieval process.

    #./cf-events.py  --token=ABC1234  --zoneid=DEF456  --zonename=example
    #./cf-report.py --twohour --zonename=example

# Advanced Analytics

I had the need to analyze firewall events in a bit more detail. For now you have to run the cf-details.py script to load these details into a sqlite db. 
This will only be of use to some, and the DB grows, so it is broken out into a seperate script for now. 

    ./cf-details.py  --token=ABC1234  --zoneid=DEF456 

    ./cf-report.py --ja3 

This is helpful for me to see JA3 fingerprints with a large number of User Agents, this indicates to me that this is synthetic traffic. 

![alt_tag](https://github.com/joemcmanus/cloudflareViewer/blob/main/img/twohourReport.jpg)
![alt_tag](https://github.com/joemcmanus/cloudflareViewer/blob/main/img/stackedReport.jpg)

